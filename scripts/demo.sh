#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
work=$(mktemp -d)
primary_pid=
secondary_pid=
ref() {
  if [[ -n "$1" ]]; then
    kill -TERM "$1" 2>/dev/null || true
    wait "$1" || true
  fi
}
cleanup() {
  local code=$?
  trap - EXIT
  ref "$secondary_pid"
  ref "$primary_pid"
  if [[ "$code" != 0 ]]; then
    cat "$work"/*.log >&2 || true
  fi
  rm -rf -- "$work"
  exit "$code"
}
trap cleanup EXIT

if [[ $# -eq 1 ]]; then
  binary=$(realpath "$1")
elif [[ $# -eq 0 ]]; then
  binary="$work/labelreef"
  (cd "$root" && go build -trimpath -o "$binary" ./cmd/labelreef)
else
  echo "usage: demo.sh [labelreef binary]" >&2
  exit 2
fi
cp -R "$root/examples" "$work/examples"
cd "$work/examples"
primary=127.0.0.1:18053
secondary=127.0.0.1:18054
primary_dns=127.0.0.1:15353
secondary_dns=127.0.0.1:15354

ctl() {
  "$binary" ctl -address "$@"
}
ask() {
  "$binary" query -address "$@"
}
expect() {
  local output="$1"
  shift
  printf '%s\n' "$output"
  for text in "$@"; do
    if ! grep -F -- "$text" <<<"$output" >/dev/null; then
      printf 'expected output to contain %s\n' "$text" >&2
      return 1
    fi
  done
}
up() {
  local id="$1" endpoint="$2"
  for retry in {1..50}; do
    if ctl "$endpoint" status >/dev/null 2>&1; then
      return 0
    fi
    kill -0 "$id"
    sleep 0.1
  done
  echo "daemon readiness deadline expired at $endpoint" >&2
  return 1
}

echo '== v1 legacy seed -> canonical file -> v1 read =='
"$binary" rewrite zones/lab-v1.json > "$work/roundtrip.json"
expect "$("$binary" inspect "$work/roundtrip.json")" '"serial": 4294967294' '"origin": "lab.test."'
"$binary" rewrite "$work/roundtrip.json" > "$work/roundtrip-again.json"
cmp "$work/roundtrip.json" "$work/roundtrip-again.json"

"$binary" serve -config primary.json >"$work/primary.log" 2>&1 &
primary_pid=$!
"$binary" serve -config secondary.json >"$work/secondary.log" 2>&1 &
secondary_pid=$!
up "$primary_pid" "$primary"
up "$secondary_pid" "$secondary"

echo '== authority, negative, wildcard, UDP truncation =='
expect "$(ask "$primary_dns" www.child.lab.test. A)" '"authoritative": true' '192.0.2.162'
expect "$(ask "$primary_dns" absent.branch.lab.test. A)" '"code": "NXDOMAIN"' '"ttl": 45'
expect "$(ask "$primary_dns" synthesized.lab.test. A)" '"code": "NOERROR"' '192.0.2.99'
expect "$(ask "$primary_dns" -retry-tcp=false bulletin.lab.test. TXT)" '"truncated": true' '"answer": []'
expect "$(ask "$primary_dns" bulletin.lab.test. TXT)" '"transport": "tcp"' '"retried_tcp": true' 'sample report'
expect "$(ask "$secondary_dns" www.lab.test. A)" '"code": "REFUSED"'
if [[ -n "${LABELREEF_DIG:-}" ]]; then
  echo '== BIND dig over UDP and TCP =='
  dig_at() {
    "$LABELREEF_DIG" @127.0.0.1 -p 15353 +time=2 +tries=1 +norecurse +nocookie "$@"
  }
  expect "$(dig_at www.lab.test. A)" 'status: NOERROR' 'flags: qr aa' '192.0.2.10' '192.0.2.11'
  expect "$(dig_at absent.branch.lab.test. A)" 'status: NXDOMAIN' 'lab.test.' '4294967294'
  expect "$(dig_at +noedns +ignore bulletin.lab.test. TXT)" 'flags: qr aa tc' 'ANSWER: 0'
  expect "$(dig_at +tcp bulletin.lab.test. TXT)" 'ANSWER: 6' 'sample report'
  expect "$(dig_at +tcp lab.test. AXFR)" '192.0.2.10' 'XFR size:'
fi

echo '== initial AXFR; two IXFR edits wrapping through 0 =='
expect "$(ctl "$secondary" sync lab.test.)" '"kind": "axfr"' '"serial": 4294967294'
expect "$(ask "$secondary_dns" www.lab.test. A)" '192.0.2.10' '192.0.2.11'
"$binary" xfr -address "$primary_dns" -trace "$work/bootstrap.xfr" lab.test. > "$work/bootstrap.json"
"$binary" replay "$work/bootstrap.xfr" > "$work/bootstrap-replay.json"
cmp "$work/bootstrap.json" "$work/bootstrap-replay.json"
expect "$(ctl "$primary" edit edits/to-4294967295.json)" '"serial": 4294967295'
expect "$(ctl "$primary" edit edits/to-0.json)" '"serial": 0'
expect "$(ctl "$secondary" sync lab.test.)" '"kind": "ixfr"' '"serial": 0'
if [[ -n "${LABELREEF_DIG:-}" ]]; then
  expect "$(dig_at +tcp lab.test. IXFR=4294967294)" '4294967295' '192.0.2.12' 'XFR size:'
fi
"$binary" xfr -address "$primary_dns" -base "$work/bootstrap.json" -trace "$work/wrap.xfr" lab.test. > "$work/wrap.json"
"$binary" replay -base "$work/bootstrap.json" "$work/wrap.xfr" > "$work/wrap-replay.json"
cmp "$work/wrap.json" "$work/wrap-replay.json"
ctl "$secondary" export lab.test. > "$work/mirror-wrap.json"
expect "$("$binary" compare "$work/wrap.json" "$work/mirror-wrap.json")" '"equal": true'
expect "$(ask "$secondary_dns" www.lab.test. A)" '192.0.2.12' '192.0.2.11'
expect "$(ask "$secondary_dns" wrapped.lab.test. TXT)" 'sequence wrapped'
expect "$(ctl "$secondary" sync lab.test.)" '"kind": "unchanged"' '"changed": false'

echo '== retention gap -> AXFR fallback =='
for n in 1 2 3; do
  expect "$(ctl "$primary" edit "edits/to-$n.json")" "\"serial\": $n"
done
expect "$(ctl "$secondary" sync lab.test.)" '"kind": "axfr-fallback"' '"serial": 3'
expect "$(ask "$secondary_dns" head.lab.test. A)" '192.0.2.22'

echo '== parent and child batch publication =='
expect "$(ctl "$primary" batch edits/batch-parent-child-demo.json)" '"parent": {' '"origin": "lab.test."' '"serial": 4' '"child": {' '"origin": "child.lab.test."' '"serial": 18'
expect "$(ask "$primary_dns" static.child.lab.test. A)" '"authoritative": true' '192.0.2.164'
expect "$(ask "$primary_dns" ns2.lab.test. A)" '192.0.2.63'
echo '== a stale member rejects both zones =='
if ctl "$primary" batch edits/batch-parent-child-demo-stale.json >"$work/stale.log" 2>&1; then
  echo 'stale batch unexpectedly succeeded' >&2
  exit 1
fi
expect "$(cat "$work/stale.log")" 'differs' 'lab.test.'
expect "$(ctl "$primary" export child.lab.test.)" 'hostmaster.child.lab.test. 18 90 30' 'static.child.lab.test.'

echo '== atomic route replacement reaches the parent cut =='
cp primary-parent-only.json primary-next.json
mv primary-next.json primary.json
expect "$(ctl "$primary" reload)" '"origin": "lab.test."'
expect "$(ask "$primary_dns" www.child.lab.test. A)" '"authoritative": false' 'ns.child.lab.test.' '192.0.2.61'

echo '== restart and read the durable v1 state =='
kill -TERM "$secondary_pid"
wait "$secondary_pid"
secondary_pid=
"$binary" serve -config secondary.json >"$work/secondary-reopen.log" 2>&1 &
secondary_pid=$!
up "$secondary_pid" "$secondary"
expect "$(ctl "$secondary" status)" '"serial": 3' '"generation": 3'
expect "$(ask "$secondary_dns" -tcp head.lab.test. A)" '192.0.2.22'
expect "$("$binary" state "$work"/var/secondary/*.json)" '"serial": 3' '"from": 0' '"to": 3'
if [[ -n "${LABELREEF_ARTIFACT_DIR:-}" ]]; then
  cp "$work"/{roundtrip.json,bootstrap.json,bootstrap.xfr,wrap.json,wrap.xfr} "$LABELREEF_ARTIFACT_DIR/"
  cp "$work"/var/secondary/*.json "$LABELREEF_ARTIFACT_DIR/mirror-state-v1.json"
fi
echo 'Labelreef demo passed'
