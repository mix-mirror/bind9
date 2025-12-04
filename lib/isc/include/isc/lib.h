/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/*
 * BIND9 constructor/destructor README
 * -----------------------------------
 *
 * A function tagged with `__attribute__((__destructor__))` is called right
 * after `main()` returns (or `exit()` is called; see `man atexit` for more
 * details). However is a valid assumption _only_ if the function is defined
 * inside the binary.
 *
 * If the function is defined as part of a shared library, it will
 * be called only when the library is unloaded by the OS linker. There is no
 * way to control the order in which two destructor functions "A" and "B" are
 * called if they are defined in separate libraries, because it depends
 * on the order in which the OS linker unloads the libraries.
 *
 * As a consequence, all contructor/destructor functions of BIND9 must be
 * defined in `lib/<lib>/include/<lib>/lib.h` header and such header must be
 * included in each binaries (in each C file defining `main()`) and must not be
 * included in any library.
 *
 * Otherwise, there might be interference. For example, LSAN which could run
 * before the BIND9 destructor functions have cleaned up remaining non-root
 * memory.
 *
 * The order of the calls between the BIND9 constructors/destructors is enforced
 * by a reference counter in the `<lib>__lib_{initialize,shutdown}` functions.
 */

#pragma once

#include <isc/util.h>

void
isc__lib_initialize(void);
void
isc__lib_shutdown(void);

void
isc_lib_initialize(void) __attribute__((__constructor__));
void
isc_lib_shutdown(void) __attribute__((__destructor__));

void
isc_lib_initialize(void) {
	isc__lib_initialize();
}

void
isc_lib_shutdown(void) {
	isc__lib_shutdown();
}
