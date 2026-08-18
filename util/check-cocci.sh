#!/bin/sh
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

ret=0

run_spatch() {
  local spatch=$1
  shift
  local spatchargs="$@"
  local patch="$(dirname "$spatch")/$(basename "$spatch" .spatch).patch"

  : >"$patch"
  echo "Applying semantic patch $spatch..."
  spatch --jobs "${TEST_PARALLEL_JOBS:-1}" --sp-file "$spatch" --macro-file-builtins cocci/macros.def --use-gitgrep --dir "." --include-headers $spatchargs >>"$patch" 2>cocci.stderr
  cat cocci.stderr
  if grep -q -e "parse error" -e "EXN: Failure" -e "WARNING" cocci.stderr; then
    ret=1
  fi
  if [ "$(wc <"$patch" -l)" -gt "0" ]; then
    cat "$patch"
    ret=1
  else
    rm "$patch"
  fi
}

spatchargs=""
spatchfile=""

for arg in "$@"; do
  if [ "$arg" = "--" ]; then
    shift
    spatchargs="$@"
    break
  fi

  if [ -z "$spatchfile" ]; then
    spatchfile="$arg"
    shift
  else
    echo "USAGE: $0 [spatch-file] [-- spatch arguments]"
    exit 1
  fi
done

if [ -n "$spatchfile" ]; then
  run_spatch $spatchfile $spatchargs
else
  for spatch in cocci/*.spatch; do
    run_spatch $spatch --very-quiet $spatchargs
  done
fi

rm -f cocci.stderr

exit $ret
