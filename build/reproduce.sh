#!/usr/bin/env bash
#
# Builds the enclave image file of HEAD twice, the second time without any cache, and fails
# unless PCR0, PCR1 and PCR2 (and the rest of measurements.json) are the same.
#
#   build/reproduce.sh --release NAME --out DIR
#
# DIR receives enclave.eif and measurements.json of the first build, and first/ and second/
# with both builds.

set -euo pipefail

RELEASE=""
OUT=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --release) RELEASE="${2:-}"; shift 2 ;;
        --out) OUT="${2:-}"; shift 2 ;;
        *) sed -n '3,10p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2 ;;
    esac
done
[ -n "$RELEASE" ] && [ -n "$OUT" ] || { sed -n '3,10p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }

HERE=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$OUT"

"$HERE/build.sh" --release "$RELEASE" --out "$OUT/first" >/dev/null
"$HERE/build.sh" --release "$RELEASE" --out "$OUT/second" --no-cache >/dev/null

measurements() {
    grep -E '^  "pcr[012]": "[0-9a-f]{96}",$' "$1"
}
first=$(measurements "$OUT/first/measurements.json")
second=$(measurements "$OUT/second/measurements.json")
[ "$(printf '%s\n' "$first" | wc -l)" -eq 3 ] || {
    echo "reproduce: the first build has no PCR0, PCR1 and PCR2" >&2
    exit 1
}
printf 'first build:\n%s\nsecond build:\n%s\n' "$first" "$second" >&2
if [ "$first" != "$second" ]; then
    echo "reproduce: the two builds differ: the enclave image is not reproducible" >&2
    exit 1
fi
# Everything else measurements.json names (the program, the inputs) must be the same too.
if ! cmp -s "$OUT/first/measurements.json" "$OUT/second/measurements.json"; then
    diff "$OUT/first/measurements.json" "$OUT/second/measurements.json" >&2 || true
    echo "reproduce: the measurements of the two builds differ" >&2
    exit 1
fi
echo "reproduce: PCR0, PCR1 and PCR2 are the same in both builds" >&2
cp "$OUT/first/enclave.eif" "$OUT/first/measurements.json" "$OUT/"
cat "$OUT/measurements.json"
