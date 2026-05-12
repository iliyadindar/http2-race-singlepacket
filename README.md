# race.go — single-packet attack, reviewed final

## Build
    sudo apt install -y golang-go        # or use the latest from go.dev
    cd ~/race
    go mod tidy
    go build -ldflags="-s -w" -o race race.go

## Run
    # Update -host and -cookie for your current lab session, then:
    ./race -conns=1 -streams=100 -ping

## What's different from v3

| | v3 | final |
|---|---|---|
| RST_STREAM handling | ❌ hung waiting | ✓ counts as stream end |
| GOAWAY handling | ❌ hung waiting | ✓ aborts cleanly |
| PING handling | ❌ ignored (protocol violation) | ✓ acked properly |
| Server sync | 5ms sleep guess | ✓ PING+ACK deterministic |
| Single-conn path | goroutine+channel overhead | ✓ straight-line code |
| Output | status codes only | ✓ win-balance histogram |

## Tuning — try in this order

1. **Default** — `./race -conns=1 -streams=100`
   Single TCP connection, 100 streams in one packet. Tightest possible sync.
2. **Fewer streams** — `./race -conns=1 -streams=30`
   PortSwigger's research shows 20–30 is often the sweet spot. Larger bursts can DEGRADE win rate due to processing serialization.
3. **Sleep instead of PING** — `./race -conns=1 -streams=100 -ping=false -preload-ms=80`
   Try if PING-sync somehow underperforms in your lab.
4. **Multi-conn** — `./race -conns=3 -streams=100`
   ONLY if single-conn doesn't ceiling out. Your earlier data shows multi-conn is usually worse.

## Honest expectation

The single-packet attack over TLS has a documented ceiling of **~20–30 wins
per attack** (PortSwigger "Smashing the State Machine", confirmed by
h2spacex, PayloadsAllTheThings, Flatt Security). You've been hitting 30–42
wins, which is at or slightly above the documented ceiling.

**No client-side optimization will exceed this for this technique.** The
limits are:
1. TCP MSS ~1460 bytes per packet
2. Each HPACK-compressed request ~50 bytes → ~30 requests/packet
3. Server's race window (microseconds) caps concurrent processing

The Flatt Security "First Sequence Sync" technique scales to 10,000
requests but only works over HTTP/2 cleartext (not TLS). Your target uses
TLS, so it doesn't apply.

To hit +400 balance you almost certainly need a non-script angle:
- A different endpoint than `/redeem`
- Multiple lab sessions/accounts
- Resetting the lab between attacks if balance persists across resets
- Examining what the "Stampede" dashboard actually exposes

If you can paste the dashboard HTML or any other endpoint you see on the
lab, I can help find the actual win path.
