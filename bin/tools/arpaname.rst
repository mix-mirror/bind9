.. Copyright (C) Internet Systems Consortium, Inc. ("ISC")
..
.. SPDX-License-Identifier: MPL-2.0
..
.. This Source Code Form is subject to the terms of the Mozilla Public
.. License, v. 2.0.  If a copy of the MPL was not distributed with this
.. file, you can obtain one at https://mozilla.org/MPL/2.0/.
..
.. See the COPYRIGHT file distributed with this work for additional
.. information regarding copyright ownership.

.. highlight: console

.. iscman:: arpaname
.. program:: arpaname
.. _man_arpaname:

arpaname - translate IP addresses to the corresponding ARPA names
-----------------------------------------------------------------

Synopsis
~~~~~~~~

:program:`arpaname` [**-o**] [**-s**] {*ipaddress/phone number/email* ...}

Options
~~~~~~~

.. option:: -o

   Decode email address into RFC 7929 OPENPGPKEY record path.
   This is the default when email address is specified.

.. option:: -s

   Decode email address into RFC 8162 SMIMEA record path.

Description
~~~~~~~~~~~

:program:`arpaname` translates IP addresses (IPv4 and IPv6) to the
corresponding IN-ADDR.ARPA or IP6.ARPA names. Can convert telephone
number starting with `+` sign into E164.ARPA name.
Decodes email addresses in form user@example.com into _openpgpkey
or _smimecert owner name.

See Also
~~~~~~~~

BIND 9 Administrator Reference Manual.
