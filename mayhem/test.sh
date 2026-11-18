#!/usr/bin/env bash
#
# mayhem/test.sh — functional oracle for PhysicsFS. Drives upstream's own test_physfs program (built
# by mayhem/build.sh with normal flags) over one small archive per format (the harness seeds, which
# are committed) and compares the file listing, file contents and CRC-32s it prints with known values.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
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


TP="$SRC/cmake-build/tests/test_physfs"
SEEDS="$SRC/mayhem/fuzz_archive/testsuite"
[ -x "$TP" ] || { echo "test_physfs missing (mayhem/build.sh should have built it)" >&2; emit_ctrf "test_physfs" 0 1 0; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

passed=0 failed=0

# pf <expected> <label> <archive> <cmd>...: run the commands after mounting <archive> at "/"; compare
# everything test_physfs prints after its banner with <expected>.
pf() {
  local expected="$(printf '%s' "$1")" label="$2" archive="$3"; shift 3
  local args=("mount $archive / 1") c
  for c in "$@"; do args+=("$c"); done
  args+=("quit")
  local out
  out="$("$TP" "${args[@]}" </dev/null 2>&1 | sed '1,/^Enter commands/d')"
  if [ "$out" = "$expected" ]; then
    passed=$((passed + 1))
  else
    failed=$((failed + 1))
    echo "FAIL: $label" >&2
    echo "--- expected" >&2; printf '%s\n' "$expected" >&2
    echo "--- got" >&2; printf '%s\n' "$out" >&2
  fi
}

# refused <label> <archive>: mounting must fail and nothing from it may be listed
refused() {
  local out
  out="$("$TP" "mount $2 / 1" "ls /" "quit" </dev/null 2>&1 | sed '1,/^Enter commands/d')"
  case "$out" in
    Failure.*"total (0) files.") passed=$((passed + 1)) ;;
    *) failed=$((failed + 1)); echo "FAIL: $1: $out" >&2 ;;
  esac
}

crc() { python3 -c "import sys,zlib; print('0x%X' % zlib.crc32(bytes(range(int(sys.argv[1]))) * int(sys.argv[2])))" "$@"; }
HELLO='hello world
hello world
hello world
'
CRC_DATA="$(crc 64 1)"
NL=$'\n'

# seed byte 0 is the fuzz harness's selector; the archive is the rest of the file
for fmt in grp:grp wad:wad hog:hog mvl:mvl qpak:pak csm:bin pod:pod vdf:vdf; do
  seed="${fmt%%:*}" ext="${fmt##*:}"
  tail -c +2 "$SEEDS/$seed" > "$WORK/t.$ext"
  hello=HELLO.TXT; [ "$seed" = wad ] && hello=HELLO.TX    # WAD names are 8 characters
  pf "Successful.${NL}DATA.BIN${NL}$hello${NL}${NL} total (2) files." "$seed: listing" "$WORK/t.$ext" "ls /"
  pf "Successful.${NL}${HELLO}${NL}" "$seed: file content" "$WORK/t.$ext" "cat $hello"
  pf "Successful.${NL}CRC32 for DATA.BIN: $CRC_DATA" "$seed: crc32" "$WORK/t.$ext" "crc32 DATA.BIN"
done

for z in deflate stored; do
  tail -c +2 "$SEEDS/zip_$z" > "$WORK/z$z.zip"
  pf "Successful.${NL}deeper${NL}inner.bin${NL}${NL} total (2) files." "zip $z: subdirectory listing" "$WORK/z$z.zip" "ls sub"
  pf "Successful.${NL}CRC32 for sub/inner.bin: $(crc 256 2)" "zip $z: crc32 of nested file" "$WORK/z$z.zip" "crc32 sub/inner.bin"
  pf "Successful.${NL}$(python3 -c "print('zip seed ' * 40, end='')")${NL}" "zip $z: file content" "$WORK/z$z.zip" "cat top.txt"
done

# archives that must be refused
head -c 300 /dev/zero > "$WORK/zeros.zip"
refused "unrecognised archive is refused" "$WORK/zeros.zip"
tail -c +2 "$SEEDS/csm" | head -c 20 > "$WORK/trunc.bin"
refused "truncated CSM directory is refused" "$WORK/trunc.bin"

emit_ctrf "test_physfs" "$passed" "$failed" 0
