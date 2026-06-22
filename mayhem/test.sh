#!/usr/bin/env bash
#
# libwebsockets/mayhem/test.sh — RUN libwebsockets' own self-contained gunzip selftest (built by
# mayhem/build.sh with normal flags) as a byte-exact golden oracle, and emit a CTRF summary.
# exit 0 iff every case passes.
#
# PATCH-grade oracle over the FUZZED path: lws_gunzip_oracle drives the SAME inflator the fuzzer hits
# (lws_upng_inflator_create -> lws_upng_inflate_data -> destroy). Each case gzip-compresses a known
# payload, inflates it through the oracle (<gz> <out>), and asserts the inflated bytes equal the
# original AND the tool returns 0. A no-op / "return 0" patch to the inflator, or any change that
# corrupts the DEFLATE decode, makes the round-trip mismatch and fails the suite — the oracle cannot
# be satisfied without a correct inflate. No network peer required; runs offline.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=/mayhem}"
cd "$SRC"

ORACLE="$SRC/mayhem-tests/lws_gunzip_oracle"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

if [ ! -x "$ORACLE" ]; then
  echo "missing $ORACLE — run mayhem/build.sh first" >&2
  emit_ctrf "lws-gunzip" 0 1 0; exit 2
fi
if ! command -v gzip >/dev/null 2>&1; then
  echo "gzip not available — cannot generate golden inputs" >&2
  emit_ctrf "lws-gunzip" 0 1 0; exit 2
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Golden round-trip payloads exercising distinct DEFLATE behaviour:
#  - short literal text   (mostly literals)
#  - highly repetitive    (LZ77 back-references)
#  - larger varied text   (multiple DEFLATE blocks)
make_payloads() {
  printf 'libwebsockets gunzip selftest: the quick brown fox jumps over the lazy dog.\n' > "$WORK/p1"
  python3 - "$WORK/p2" <<'PY' 2>/dev/null || head -c 200000 /dev/zero | tr '\0' 'A' > "$WORK/p2"
import sys
open(sys.argv[1],"wb").write((b"ABCDEFGH"*32768))
PY
  { for i in $(seq 1 4000); do printf 'line %d: libwebsockets inflate golden oracle payload row\n' "$i"; done; } > "$WORK/p3"
}
make_payloads

PASS=0; FAIL=0
for p in p1 p2 p3; do
  gzip -n -c "$WORK/$p" > "$WORK/$p.gz"
  if "$ORACLE" "$WORK/$p.gz" "$WORK/$p.out" >/dev/null 2>&1 \
     && cmp -s "$WORK/$p" "$WORK/$p.out"; then
    echo "PASS gunzip round-trip: $p ($(wc -c < "$WORK/$p") bytes)"
    PASS=$((PASS+1))
  else
    echo "FAIL gunzip round-trip: $p (inflated output != original or tool errored)"
    FAIL=$((FAIL+1))
  fi
done

emit_ctrf "lws-gunzip" "$PASS" "$FAIL" 0
