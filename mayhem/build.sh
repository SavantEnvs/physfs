#!/usr/bin/env bash
#
# mayhem/build.sh — builds PhysicsFS twice (sanitized+instrumented for the fuzz harnesses, normal flags
# for the functional suite), both out of tree under cmake-build/ (gitignored upstream, so
# `git clean -ffdX` wipes them), then links each harness against the sanitized static library.
# Every dependency is in the image (cmake, clang, python3); nothing is fetched, so the offline re-run works.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

SRC="${SRC:-/mayhem}"
cd "$SRC"

# 1) Sanitized + SanCov-instrumented library (static, no docs/tests/install).
FUZZ_CFLAGS="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS"
cmake -S . -B cmake-build/fuzz -G Ninja \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_FLAGS="$FUZZ_CFLAGS" \
    -DPHYSFS_BUILD_SHARED=OFF -DPHYSFS_BUILD_STATIC=ON \
    -DPHYSFS_BUILD_TEST=OFF -DPHYSFS_BUILD_DOCS=OFF -DPHYSFS_INSTALL=OFF
cmake --build cmake-build/fuzz -j"$MAYHEM_JOBS"

# 2) Harnesses: libFuzzer binary + standalone reproducer, both with leak detection compiled off.
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o cmake-build/lsan_off.o
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o cmake-build/standalone_main.o

for h in fuzz_archive fuzz_text; do
    $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE -Isrc \
        "mayhem/$h.c" cmake-build/lsan_off.o cmake-build/fuzz/libphysfs.a -o "$SRC/$h"
    $CC $SANITIZER_FLAGS $DEBUG_FLAGS -Isrc \
        "mayhem/$h.c" cmake-build/standalone_main.o cmake-build/lsan_off.o cmake-build/fuzz/libphysfs.a \
        -o "$SRC/$h-standalone"
done

# 3) The project's own interactive test program, with NORMAL flags, for mayhem/test.sh.
cmake -S . -B cmake-build/tests -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" \
    -DPHYSFS_BUILD_SHARED=OFF -DPHYSFS_BUILD_STATIC=ON \
    -DPHYSFS_BUILD_TEST=ON -DPHYSFS_BUILD_DOCS=OFF -DPHYSFS_INSTALL=OFF
cmake --build cmake-build/tests -j"$MAYHEM_JOBS" --target test_physfs
