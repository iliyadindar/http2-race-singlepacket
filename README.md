# http2-race-singlepacket

A small Go tool that performs an **HTTP/2 single-packet race attack** against a
target endpoint. It packs many requests into one TCP packet so the server
receives them at (almost) exactly the same instant, exposing race conditions
in handlers that check-then-act on shared state (e.g. coupon redemption,
balance top-ups, one-time tokens).

> **Use this only against systems you own or are explicitly authorised to
> test** (your own labs, bug-bounty programs that allow it, PortSwigger Web
> Security Academy labs, CTF challenges). Unauthorised use is illegal in most
> jurisdictions.

---

## What is a single-packet race?

A web server that does something like:

```
if user.balance < limit:        # check
    user.balance += amount      # act
```

is safe under normal traffic because requests arrive one after another. But
if **many requests arrive in the same instant**, several threads can pass the
check before any of them performs the update — and you get the action
multiple times.

The trick is getting requests to arrive at the same instant. HTTP/1 can't do
it (one request per TCP packet). HTTP/2 can: you open many streams on one
connection, send all the headers first, and then send all the final frames
(the bytes that tell the server "this request is complete, go handle it") in
**one TCP packet**. The server reads that packet, sees N completed requests
at once, and dispatches them in parallel.

This tool implements that attack end-to-end: TLS + HTTP/2 setup, stream
pre-loading, deterministic sync with the server, and a single `write()` of
the trigger bytes.

Original research: PortSwigger, [Smashing the State Machine](https://portswigger.net/research/smashing-the-state-machine).

---

## Requirements

- Go 1.20+ (`sudo apt install golang-go` on Debian/Ubuntu, or grab the latest
  from <https://go.dev/dl/>)
- Linux/macOS (Windows untested)
- Network access to the target on port 443
- A valid session cookie (or whatever auth the target uses)

## Build

```sh
git clone https://github.com/iliyadindar/http2-race-singlepacket.git
cd http2-race-singlepacket
go mod tidy
go build -ldflags="-s -w" -o race race.go
```

You'll get a single `race` binary in the current directory.

## Quick start

```sh
./race \
    -host='your-lab.example.com' \
    -cookie='session=YOUR_SESSION_COOKIE_VALUE' \
    -conns=1 -streams=100 -ping -target=405
```

Sample output:

```
[*] Target  : https://your-lab.example.com/redeem
[*] Burst   : 100 reqs (1 × 100)
[*] Sync    : PING+ACK (deterministic)

[r01] 2.13s  resp=100  wins=34  max_bal=175  win_balances: 1×10 2×25 …
```

- `wins` = number of responses where the server returned `"ok":true`
- `max_bal` = highest balance any response observed
- `win_balances` = histogram showing which balance values came back successful

---

## Automated end-to-end: `run.sh`

If your target is a pwnbox-style lab where you can sign up disposable
accounts and the flag endpoint is gated by balance, use the bundled
`run.sh` to loop signup → race → flag-check until you win.

```sh
./run.sh 85dbd3eba2a9.pwnbox-lab.com
```

Each attempt it:

1. `POST /signup` (body `name=a`) and pulls the `session=` cookie from
   `Set-Cookie`.
2. Runs `race` with the best-known config (`-conns=20 -streams=4
   -ping=false -preload-ms=5`), pinned to CPU 0 via `taskset` if
   available.
3. `GET /flag` with the cookie. If the response has `balance >= 400` and
   no `"error"` field, prints the flag body and exits.
4. Otherwise `POST /logout` and loops with a fresh signup.

Overridable env vars: `MAX_ATTEMPTS` (default 15), `CONNS`, `STREAMS`,
`PRELOAD_MS`, `TARGET_BAL`. The script also tries to set the CPU governor
to `performance` on start (silent no-op if not available).

---

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `-host` | `target.example.com` | Target hostname (no scheme, no path) |
| `-cookie` | (placeholder) | Full cookie header value, e.g. `session=abc123` |
| `-conns` | `1` | Number of parallel TCP connections |
| `-streams` | `100` | HTTP/2 streams per connection (server cap is usually 100) |
| `-ping` | `true` | Use PING+ACK to sync with the server (deterministic). Set `-ping=false` to fall back to a fixed sleep. |
| `-preload-ms` | `50` | Sleep before firing (only used when `-ping=false`) |
| `-target` | `405` | Stop once any response reports `balance >= target` |
| `-rounds` | `3` | Max attempts before giving up |

The endpoint hit is hard-coded to `/redeem` in `race.go` — edit the `path`
variable if your target uses something else.

---

## Tuning guide

There is no single "best" config — it depends on the server. Try in this
order:

### 1. Single connection, max streams (tightest sync)
```sh
./race -conns=1 -streams=100 -ping
```
One TCP packet, all triggers fire together. This is what the single-packet
technique is designed for. **Theoretical ceiling: ~20–30 wins** on TLS,
because TCP MSS (~1460 bytes) limits how many trigger frames fit in one
packet.

### 2. Multi-connection burst
```sh
./race -conns=30 -streams=4 -ping=false -preload-ms=5
```
Trades single-packet precision for total request volume. Works well when
the server's race window is wider than the inter-connection jitter
(~microseconds). Often beats single-conn on labs that don't hit the
documented ceiling because the bottleneck was server-side concurrency, not
client-side sync.

### 3. Fewer streams, single conn
```sh
./race -conns=1 -streams=30 -ping
```
Larger bursts sometimes *degrade* win rate because the server serialises
processing past a certain queue depth. 20–30 is the documented sweet spot.

### Picking which to use
- If single-conn gives ~30 wins and you need more → switch to multi-conn.
- If multi-conn gives ~70% hit-rate → raise `-conns` until you have enough
  total requests for the wins you need.
- If hit-rate collapses when you raise `-conns` → you've hit handshake skew;
  drop back down or try `-ping=true`.

---

## How it works (under the hood)

1. **Connect** — open one (or many) TLS+HTTP/2 connections.
2. **Pre-load** — for each connection, send `streams` HEADERS frames *without*
   the END_STREAM flag. The server now has N half-open requests, waiting for
   their final byte.
3. **Sync** — send an HTTP/2 PING frame and wait for the ACK. When the ACK
   comes back, we know the server has read past all our HEADERS.
4. **Fire** — write one buffer containing N tiny `DATA` frames with the
   END_STREAM flag set, one per stream. This buffer is ~9×N bytes — small
   enough to fit in a single TCP packet for N ≤ ~160.
5. **Collect** — read responses, count wins, build the histogram.

Multi-connection mode adds an **arrive-barrier** (every fire goroutine
confirms it's parked before any of them release) plus `runtime.LockOSThread`
so the Go scheduler can't interleave the trigger writes.

---

## Limits — read this before tuning forever

The single-packet attack over **TLS** has a documented ceiling of roughly
**20–40 wins per attack**, set by:

1. TCP MSS ~1460 bytes per packet
2. HPACK-compressed request size → ~30 requests fit in one packet
3. Server's race window (microseconds) caps how many handlers can be
   "checking" at once

Sources: PortSwigger's original research, h2spacex, PayloadsAllTheThings,
Flatt Security write-ups.

**No client-side change will push past this for a given server.** If you
need more wins:

- Reset the lab between bursts (most labs consume the voucher on the first
  successful race, so round 2 always shows `wins=0`).
- Try a different endpoint if the lab exposes one.
- Use multi-connection mode to fan out more requests at the cost of perfect
  sync.
- For non-TLS targets, look at Flatt Security's "first-sequence-sync"
  technique, which scales to thousands of requests but doesn't apply here.

---

## Troubleshooting

**"Lab locked after first burst — wins won't increase."**
The voucher/coupon/token was consumed on round 1. Reset the lab in its UI
and rerun. This is not a bug — it's the heuristic in `race.go` correctly
detecting that further attempts on the same session can't win.

**`wins=0 max_bal=0` on round 1.**
The server is replying but the response shape doesn't match what the script
expects (`"ok":true` and `"balance":<n>`). Common causes:

- Cookie value passed without the cookie name (you sent the raw value
  instead of `session=VALUE`).
- The endpoint isn't `/redeem` for your lab — edit `path` in `race.go`.
- The request needs a body (gift-card code, CSRF token) and the script sends
  `content-length: 0`.

Quickest diagnostic: add `fmt.Printf("%s\n", data)` inside `harvest()` and
look at one raw response body.

**`dial failed` / `server did not negotiate h2`.**
Target doesn't speak HTTP/2 or is behind a CDN that strips it. This tool
only does h2 over TLS.

---

## File layout

```
race.go      # all the code — single file, ~450 lines, no external state
go.mod       # module + dependency on golang.org/x/net/http2
go.sum
README.md    # this file
LICENSE
```

## License

See [LICENSE](LICENSE).

## Disclaimer

For authorised security testing and education only. The author is not
responsible for misuse.
