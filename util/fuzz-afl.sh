#!/bin/sh

# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0.  If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

# Run every fuzz/*.in corpus through its AFL fuzzer for a fixed amount of
# time and fail if any input crashes the target.  Crashing inputs (whether
# found by AFL or already present as a seed that the target cannot handle)
# are replayed through the target so that the assertion or sanitizer report
# ends up in the job log, and the reproducers are left in the findings
# directory for download.
#
# Environment variables:
#   FUZZ_TIME       seconds to fuzz each target (default 60)
#   FUZZ_BUILD_DIR  meson build directory to use/create (default build-afl)
#   FUZZ_FINDINGS   directory for AFL output (default fuzz-findings)
#   FUZZ_SKIP       space-separated target names to skip (default empty)
#   CC              AFL compiler wrapper used when building (default afl-clang-fast)

set -eu

FUZZ_TIME="${FUZZ_TIME:-60}"
FUZZ_BUILD_DIR="${FUZZ_BUILD_DIR:-build-afl}"
FUZZ_FINDINGS="${FUZZ_FINDINGS:-fuzz-findings}"
FUZZ_SKIP="${FUZZ_SKIP:-}"
CC="${CC:-afl-clang-fast}"

srcdir=$(cd "$(dirname "$0")/.." && pwd)

# AFL detects crashes from the child's exit signal; if core_pattern pipes the
# core to an external handler the kernel may be slow enough that AFL mistakes
# the crash for a hang.  Point it at a plain file when we are allowed to, and
# otherwise tell AFL to proceed anyway.
if ! echo core >/proc/sys/kernel/core_pattern 2>/dev/null; then
  export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
fi

# Build the fuzzers if the build directory is not ready yet.
targets=""
for corpus in "$srcdir"/fuzz/*.in; do
  targets="$targets fuzz_$(basename "$corpus" .in)"
done

if [ ! -f "$FUZZ_BUILD_DIR/build.ninja" ]; then
  CC="$CC" meson setup "$FUZZ_BUILD_DIR" --cross-file "$srcdir/fuzz/afl.ini"
fi
# shellcheck disable=SC2086
ninja -C "$FUZZ_BUILD_DIR" $targets

mkdir -p "$FUZZ_FINDINGS"

# Replay a single input through the target and, if it crashes (killed by a
# signal, i.e. exit status >= 128), print a report.  Returns 1 on crash.
replay() {
  _bin=$1
  _input=$2
  _out=$(ASAN_OPTIONS="abort_on_error=1:symbolize=1" "$_bin" <"$_input" 2>&1) && _rc=0 || _rc=$?
  if [ "$_rc" -lt 128 ]; then
    return 0
  fi
  _size=$(wc -c <"$_input")
  echo
  echo "----- $(basename "$_bin"): crash on $_input (${_size} bytes, exit $_rc) -----"
  if [ "$_size" -le 4096 ]; then
    echo "input (hex):"
    od -An -tx1 -- "$_input"
  else
    echo "input too large to dump; reproducer saved at $_input"
  fi
  echo "output:"
  echo "$_out"
  return 1
}

fail=0
for corpus in "$srcdir"/fuzz/*.in; do
  name=$(basename "$corpus" .in)
  bin="$FUZZ_BUILD_DIR/fuzz_$name"
  test -x "$bin" || continue

  case " $FUZZ_SKIP " in
    *" $name "*)
      echo "=== $name: skipped (FUZZ_SKIP) ==="
      continue
      ;;
  esac

  out="$FUZZ_FINDINGS/$name"
  rm -rf "$out"

  echo "=== $name: fuzzing for ${FUZZ_TIME}s ==="
  # -V bounds the run; AFL_BENCH_UNTIL_CRASH stops it as soon as a crash is
  # saved.  afl-fuzz also exits non-zero when a seed already crashes the
  # target, so tolerate failure and work out below what actually happened.
  afl_rc=0
  AFL_BENCH_UNTIL_CRASH=1 AFL_NO_UI=1 AFL_NO_AFFINITY=1 AFL_SKIP_CPUFREQ=1 \
    afl-fuzz -V "$FUZZ_TIME" -m none -i "$corpus" -o "$out" -- "$bin" || afl_rc=$?

  # Crashes that AFL discovered while fuzzing.
  if find "$out/default/crashes" -name 'id:*' 2>/dev/null | grep -q .; then
    for input in "$out"/default/crashes/id:*; do
      replay "$bin" "$input" || fail=1
    done
  elif [ "$afl_rc" -ne 0 ]; then
    # afl-fuzz could not run.  The usual cause is a seed that crashes the
    # target during the dry run; replay the seeds to pinpoint and report it.
    echo "afl-fuzz exited with status $afl_rc; checking seeds"
    found=0
    for input in "$corpus"/*; do
      test -f "$input" || continue
      replay "$bin" "$input" || {
        fail=1
        found=1
      }
    done
    if [ "$found" -eq 0 ]; then
      echo "ERROR: afl-fuzz failed to start for $name and no crashing seed was found"
      fail=1
    fi
  fi
done

if [ "$fail" -eq 0 ]; then
  echo
  echo "No crashes found."
  exit 0
fi

echo
echo "########################################################################"
echo "# CRASHES DETECTED - see the reports above and $FUZZ_FINDINGS/"
echo "########################################################################"
exit 1
