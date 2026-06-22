#!/usr/bin/env bash
#
# libwebsockets/mayhem/build.sh — build warmcat/libwebsockets' OSS-Fuzz harness as a sanitized
# libFuzzer target (+ a standalone reproducer), AND a self-contained gunzip golden oracle for
# mayhem/test.sh.
#
# Fuzzed surface: libwebsockets' INTERNAL gzip/DEFLATE inflator (LWS_WITH_GZINFLATE, lib/misc/
# upng-gzip.c). The harness lws_upng_inflate_fuzzer.cpp drives
#   lws_upng_inflator_create() -> lws_upng_inflate_data(input) -> lws_upng_inflator_destroy()
# i.e. it parses attacker-controlled gzip-compressed bytes through the stateful inflator's state
# machine (gzip header parse + DEFLATE huffman/LZ77 decode). NOTE: despite the project being a
# WebSocket library, THIS harness is purely the gunzip/inflate parser path (matching OSS-Fuzz).
#
# Build contract comes from the org base ENV (CC/CXX/SANITIZER_FLAGS/LIB_FUZZING_ENGINE/SRC/
# STANDALONE_FUZZ_MAIN). We compile libwebsockets ITSELF with $SANITIZER_FLAGS so the inflator
# code (not just the harness) is instrumented.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# `=` (not `:=`) for SANITIZER_FLAGS so an explicit empty --build-arg builds with NO sanitizers.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -g}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS

cd "$SRC"

HARNESS_DIR="$SRC/mayhem/harnesses"

# ── 1) Build libwebsockets static lib WITH sanitizers (the fuzzed inflator is instrumented) ────────
#
# Mirror the OSS-Fuzz build: drop -Werror (sanitizers add warnings), and disable HTTP3/QUIC which
# upstream now defaults ON and which forces GnuTLS (we use OpenSSL). The harness only needs the
# gzip inflator (LWS_WITH_GZINFLATE, default ON). Build the static lib so the target is self-
# contained, and keep it minimal/fast.
BUILD="$SRC/mayhem-build"
rm -rf "$BUILD"; mkdir -p "$BUILD"
cmake -S "$SRC" -B "$BUILD" -G Ninja \
      -DCMAKE_BUILD_TYPE=None \
      -DCMAKE_C_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS" \
      -DCMAKE_CXX_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS" \
      -DCMAKE_EXE_LINKER_FLAGS="$SANITIZER_FLAGS" \
      -DLWS_WITH_HTTP3=OFF \
      -DLWS_WITH_GZINFLATE=ON \
      -DLWS_WITH_UPNG=ON \
      -DLWS_WITH_STATIC=ON \
      -DLWS_WITH_SHARED=OFF \
      -DLWS_WITHOUT_TESTAPPS=ON \
      -DLWS_WITH_MINIMAL_EXAMPLES=OFF \
      -DLWS_WITH_SSL=ON \
      -DCMAKE_C_COMPILER="$CC" \
      -DCMAKE_CXX_COMPILER="$CXX"
ninja -C "$BUILD" -j"$MAYHEM_JOBS" websockets

LIBLWS="$BUILD/lib/libwebsockets.a"
INC="-I$BUILD/include -I$SRC/include"
LINKLIBS="-L/usr/lib/x86_64-linux-gnu -l:libssl.so -l:libcrypto.so -lpthread -lm -ldl"

# ── 2) Build the OSS-Fuzz harness twice: libFuzzer (-> /mayhem/<name>) + standalone reproducer ─────
HARNESS=lws_upng_inflate_fuzzer

# libFuzzer target -> /mayhem/<name>
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS $INC \
    "$HARNESS_DIR/$HARNESS.cpp" $LIB_FUZZING_ENGINE \
    "$LIBLWS" $LINKLIBS \
    -o "/mayhem/$HARNESS"

# standalone reproducer (no libFuzzer runtime, reads input files one by one) -> /mayhem/<name>-standalone
# Compile the standalone main as C (its `extern int LLVMFuzzerTestOneInput` has C linkage, which
# matches the harness's `extern "C"` definition); compiling it through clang++ would C++-mangle the
# reference and break the link.
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$BUILD/standalone_main.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS $INC \
    "$HARNESS_DIR/$HARNESS.cpp" "$BUILD/standalone_main.o" \
    "$LIBLWS" $LINKLIBS \
    -o "/mayhem/$HARNESS-standalone"

echo "built $HARNESS (+ standalone)"

# ── 3) Build the self-contained gunzip golden oracle for mayhem/test.sh with NORMAL flags ──────────
#
# mayhem/harnesses/lws_gunzip_oracle.c is a tiny self-contained driver over the SAME inflator path
# the fuzzer hits (lws_upng_inflator_create -> lws_upng_inflate_data -> destroy): it inflates a gzip
# file and writes the decompressed bytes, returning 0 only on a clean (non-FATAL) inflate. test.sh
# then asserts the output is byte-exact vs the original pre-gzip payload. Built here against a
# NON-sanitized lib (normal flags, no sanitizer/UB noise) so test.sh only RUNS it.
TESTBUILD="$SRC/mayhem-tests"
rm -rf "$TESTBUILD"; mkdir -p "$TESTBUILD"
# A separate NON-sanitized libwebsockets so the oracle is a clean, self-contained binary (linking the
# sanitized $LIBLWS would pull unresolved __asan/__ubsan symbols since the oracle has no runtime).
TLIBDIR="$TESTBUILD/lib"
env -u CFLAGS -u CXXFLAGS -u SANITIZER_FLAGS \
  cmake -S "$SRC" -B "$TLIBDIR" -G Ninja \
      -DCMAKE_BUILD_TYPE=None \
      -DLWS_WITH_HTTP3=OFF -DLWS_WITH_GZINFLATE=ON -DLWS_WITH_UPNG=ON \
      -DLWS_WITH_STATIC=ON -DLWS_WITH_SHARED=OFF \
      -DLWS_WITHOUT_TESTAPPS=ON -DLWS_WITH_MINIMAL_EXAMPLES=OFF -DLWS_WITH_SSL=ON \
      -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" >/dev/null
env -u CFLAGS -u CXXFLAGS -u SANITIZER_FLAGS ninja -C "$TLIBDIR" -j"$MAYHEM_JOBS" websockets
env -u CFLAGS -u CXXFLAGS -u SANITIZER_FLAGS \
  $CC -O2 -g -I"$TLIBDIR/include" -I"$SRC/include" \
    "$HARNESS_DIR/lws_gunzip_oracle.c" \
    "$TLIBDIR/lib/libwebsockets.a" \
    -L/usr/lib/x86_64-linux-gnu -l:libssl.so -l:libcrypto.so -lpthread -lm -ldl \
    -o "$TESTBUILD/lws_gunzip_oracle"
echo "built lws_gunzip_oracle in mayhem-tests/"

echo "build.sh complete:"
ls -la "/mayhem/$HARNESS" "/mayhem/$HARNESS-standalone" "$TESTBUILD/lws_gunzip_oracle" 2>&1 || true
