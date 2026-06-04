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
FUZZ_FINDINGS="${FUZZ_FINDINGS:-fuzz-findings}"
FUZZ_SKIP="${FUZZ_SKIP:-}"
FUZZ_EXPECT_CRASH="${FUZZ_EXPECT_CRASH:-0}"
CC="${CC:-afl-clang-fast}"

# Self-test builds carry the canary define, so keep them in a separate build
# directory by default to avoid reusing a normal (canary-less) build.
if [ "$FUZZ_EXPECT_CRASH" = "1" ]; then
  FUZZ_BUILD_DIR="${FUZZ_BUILD_DIR:-build-afl-canary}"
else
  FUZZ_BUILD_DIR="${FUZZ_BUILD_DIR:-build-afl}"
fi

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

setup_args=""
if [ "$FUZZ_EXPECT_CRASH" = "1" ]; then
  # Self-test mode: build the targets with their planted canary bug.
  setup_args="-Dfuzzing-canary=enabled"
fi
if [ ! -f "$FUZZ_BUILD_DIR/build.ninja" ]; then
  # shellcheck disable=SC2086
  CC="$CC" meson setup "$FUZZ_BUILD_DIR" --cross-file "$srcdir/fuzz/afl.ini" \
    $setup_args
fi
# shellcheck disable=SC2086
ninja -C "$FUZZ_BUILD_DIR" $targets

mkdir -p "$FUZZ_FINDINGS"

# In self-test mode the corpus is a single seed that already contains the
# canary's magic prefix, so every target must crash on it during AFL's dry
# run.  This deterministically exercises each fuzzer end to end - build,
# instrumentation, the forkserver executing the target, and crash detection -
# without depending on AFL getting lucky enough to mutate its way to the magic
# (which is unreliable, especially for slow targets like dns_qp).
canary_seeds="$FUZZ_FINDINGS/.canary-seed"
if [ "$FUZZ_EXPECT_CRASH" = "1" ]; then
  rm -rf "$canary_seeds"
  mkdir -p "$canary_seeds"
  printf 'FUZZcanary' >"$canary_seeds/seed"
fi

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

  seeds="$corpus"
  [ "$FUZZ_EXPECT_CRASH" = "1" ] && seeds="$canary_seeds"

  echo "=== $name: fuzzing for ${FUZZ_TIME}s ==="
  # -V bounds the run; AFL_BENCH_UNTIL_CRASH stops it as soon as a crash is
  # saved.  afl-fuzz also exits non-zero when a seed already crashes the
  # target, so tolerate failure and work out below what actually happened.
  afl_rc=0
  AFL_BENCH_UNTIL_CRASH=1 AFL_NO_UI=1 AFL_NO_AFFINITY=1 AFL_SKIP_CPUFREQ=1 \
    afl-fuzz -V "$FUZZ_TIME" -m none -i "$seeds" -o "$out" -- "$bin" || afl_rc=$?

  # Did this target crash?  Either AFL saved a crash while fuzzing, or a seed
  # already crashed the target during the dry run (afl-fuzz then exits != 0).
  crashed=0
  if find "$out/default/crashes" -name 'id:*' 2>/dev/null | grep -q .; then
    crashed=1
    # In normal mode replay the crashes to put a report in the log; in
    # self-test mode the crash is the expected canary, so stay quiet.
    if [ "$FUZZ_EXPECT_CRASH" != "1" ]; then
      for input in "$out"/default/crashes/id:*; do
        replay "$bin" "$input" || true
      done
    fi
  elif [ "$afl_rc" -ne 0 ]; then
    # afl-fuzz could not run.  The usual cause is a seed that crashes the
    # target during the dry run (always the case in self-test mode); replay the
    # seeds to pinpoint and report it.
    echo "afl-fuzz exited with status $afl_rc; checking seeds"
    for input in "$seeds"/*; do
      test -f "$input" || continue
      replay "$bin" "$input" || crashed=1
    done
    if [ "$crashed" -eq 0 ]; then
      echo "ERROR: afl-fuzz failed to start for $name and no crashing seed was found"
      fail=1
    fi
  fi

  if [ "$FUZZ_EXPECT_CRASH" = "1" ]; then
    # Self-test: every target must rediscover its planted canary.
    if [ "$crashed" -eq 1 ]; then
      echo "$name: canary found"
    else
      echo "ERROR: $name did not find its canary within ${FUZZ_TIME}s"
      fail=1
    fi
  elif [ "$crashed" -eq 1 ]; then
    fail=1
  fi
done

if [ "$FUZZ_EXPECT_CRASH" = "1" ]; then
  if [ "$fail" -eq 0 ]; then
    echo
    echo "Self-test passed: every fuzzer found its canary."
    exit 0
  fi
  echo
  echo "########################################################################"
  echo "# SELF-TEST FAILED - a fuzzer did not find its canary (see above)"
  echo "########################################################################"
  exit 1
fi

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
