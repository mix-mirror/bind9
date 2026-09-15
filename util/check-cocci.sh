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

MACRO_ALLOWLIST_PATTERNS="
ISC_LIST
ISC_LINK
ISC_SIEVE
ISC_SLIST
ISC_SLINK
ISC_OS_CACHELINE_SIZE
_ISC_MEM_FILELINE
UV_HANDLE_TYPE_MAP
DBNODE_FIELDS
DNS_QPREADER_FIELDS
DNS__DB_FLARG_PASS
DNS__DB_FILELINE
FLARG_PASS
ISC_RUN_TEST_.+
ISC_SETUP_TEST_.+
ISC_TEARDOWN_TEST_.+
ISC_LOOP_TEST_.+
ISC_LOOP_SETUP_.+
ISC_LOOP_TEARDOWN_.+
ISC_TEST_DECLARE
ISC_TEST_LIST_.+
ISC_TEST_ENTRY
ISC_TEST_ENTRY_.+
"
MACRO_INCLUDE_FLAGS="
-Ilib/isc/include
-Ilib/dns/include
-Itests/include
"
MACRO_HEADER_FLAGS="
-include isc/sieve.h
-include isc/slist.h
-include dns/qp.h
-include tests/isc.h
-include lib/isc/netmgr/netmgr-int.h
"
COCCI_MACROS_FILE="cocci/generated.def"

generate_macro_definitions() {
  local definitions pattern

  # Extract allowlisted definitions using the preprocessor
  # -M -MG tolerates missing generated headers; send dependencies to /dev/null.
  # Use GCC explicitly: Clang emits no macro definitions with -dM -M.
  definitions=$(gcc ${CPPFLAGS:-} -dM -M -MG -MF /dev/null -x c \
    $MACRO_INCLUDE_FLAGS $MACRO_HEADER_FLAGS /dev/null) || return 1

  cp cocci/macros.def "$COCCI_MACROS_FILE" || return 1
  for pattern in $MACRO_ALLOWLIST_PATTERNS; do
    if ! printf '%s\n' "$definitions" | grep -E "^#define (${pattern})(\(|[[:space:]]|$)" >>"$COCCI_MACROS_FILE"; then
      echo "Coccinelle: no definitions matching $pattern" >&2
      return 1
    fi
  done
}

run_spatch() {
  local spatch=$1
  shift
  local spatchargs="$@"
  local patch="$(dirname "$spatch")/$(basename "$spatch" .spatch).patch"

  : >"$patch"
  echo "Applying semantic patch $spatch..."
  spatch --jobs "${TEST_PARALLEL_JOBS:-1}" --sp-file "$spatch" --macro-file-builtins "$COCCI_MACROS_FILE" --use-gitgrep --dir "." --include-headers $spatchargs >>"$patch" 2>cocci.stderr
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

generate_macro_definitions || exit 1

if [ -n "$spatchfile" ]; then
  run_spatch $spatchfile $spatchargs
else
  for spatch in cocci/*.spatch; do
    run_spatch $spatch --very-quiet $spatchargs
  done
fi

rm -f cocci.stderr

exit $ret
