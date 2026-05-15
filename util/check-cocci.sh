#!/bin/bash
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

if ! command -v spatch >/dev/null 2>&1; then
  echo "$0: spatch is not installed" >&2
  exit 2
fi

ret=0

run_spatch() {
  local spatch="$1"
  shift
  local patch
  patch="$(dirname "$spatch")/$(basename "$spatch" .spatch).patch"

  echo "Applying semantic patch $spatch..."
  spatch --jobs "${TEST_PARALLEL_JOBS:-1}" --sp-file "$spatch" --use-gitgrep --dir "." --include-headers "$@" >"$patch" 2>cocci.stderr
  cat cocci.stderr
  if grep -q -i -e "error" -e "warning" -e "failure" cocci.stderr; then
    ret=1
  fi
  if [ -s "$patch" ]; then
    cat "$patch"
    ret=1
  else
    rm "$patch"
  fi
}

spatchfile=""

while [ $# -gt 0 ]; do
  if [ "$1" = "--" ]; then
    shift
    break
  fi

  if [ -z "$spatchfile" ]; then
    spatchfile=$1
    shift
  else
    echo "USAGE: $0 [spatch-file] [-- spatch arguments]"
    exit 1
  fi
done

if [ -n "$spatchfile" ]; then
  run_spatch "$spatchfile" "$@"
else
  for spatch in cocci/*.spatch; do
    run_spatch "$spatch" --very-quiet "$@"
  done
fi

rm -f cocci.stderr

exit $ret
