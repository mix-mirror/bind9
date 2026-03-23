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

from pathlib import Path

import shutil

from .kasp import Key
from .log import debug, info
from .run import EnvCmd
from .template import Nameserver, TemplateEngine, TrustAnchor, Zone
from .vars.algorithms import Algorithm

NS1 = Nameserver("ns1", "10.53.0.1")

KEYDIR = "keys"
ZONEDIR = "zones"


def copy_dssets(delegations: list[Zone], ns: Nameserver):
    for zone in delegations:
        try:
            shutil.copy(f"{zone.ns.name}/dsset-{zone.name}.", ns.name)
        except FileNotFoundError:
            debug(f"{zone.name}: delegation is insecure")
        else:
            debug(f"{zone.name}: delegation is secure")


def generate_key(zone: Zone, params: str = "", alg: Algorithm | None = None) -> Key:
    debug(f"{zone.name}: creating key")
    keydir = Path(zone.ns.name) / KEYDIR
    keydir.mkdir(exist_ok=True)
    if alg is None:
        alg = Algorithm.default()
    keygen = EnvCmd("KEYGEN", f"-q -a {alg.number} -b {alg.bits} -K {KEYDIR} -L 3600")
    key_name = keygen(f"{params} {zone.name}", cwd=zone.ns.name).out.strip()
    return Key(key_name, keydir=keydir)


def render_signed_zone(
    zone: Zone, delegations: list[Zone], keys: list[Key], template: str | None = None
):
    debug(f"{zone.name}: rendering zone data and signing")

    templates = TemplateEngine(".")
    signer = EnvCmd("SIGNER", f"-S -g -K {KEYDIR}")

    assert zone.filename.endswith(".signed")
    basename = zone.filename[:-7]

    if template is None:
        template = f"{basename}.j2.manual"

    infile = f"{basename}.in"
    outfile = f"{basename}.signed"
    data = {
        "origin": zone,
        "delegations": delegations,
        "dnskeys": [key.dnskey for key in keys],
    }
    templates.render(
        f"{zone.ns.name}/{zone.dir}/{infile}",
        data,
        template=f"{zone.ns.name}/{zone.dir}/{template}",
    )

    signer(
        f"-P -x -O full -o {zone.name} -f {zone.dir}/{outfile} {zone.dir}/{infile}",
        cwd=zone.ns.name,
    )


def configure_signed_zone(
    zone: Zone, delegations: list[Zone], template: str | None = None
) -> list[Key]:
    info(f"{zone.name}: create zone with delegations and sign")

    copy_dssets(delegations, zone.ns)

    ksk = generate_key(zone, "-f KSK")
    zsk = generate_key(zone)
    keys = [ksk, zsk]

    render_signed_zone(zone, delegations, keys, template)
    return keys


def configure_signed_root(delegations: list[Zone], ns: Nameserver = NS1) -> TrustAnchor:
    zone = Zone(".", "root.db.signed", ns)

    keys = configure_signed_zone(zone, delegations)
    ksk = keys[0]

    return ksk.into_ta("static-ds")
