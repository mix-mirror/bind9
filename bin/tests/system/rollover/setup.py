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

import shutil
from typing import List

import isctest
from isctest.kasp import private_type_record
from isctest.template import Nameserver, TrustAnchor, Zone
from rollover.common import default_algorithm


class CmdHelper:
    def __init__(self, env_name: str, base_params: str = ""):
        self.bin_path = os.environ[env_name]
        self.base_params = base_params

    def __call__(self, params: str, **kwargs):
        args = f"{self.base_params} {params}".split()
        return isctest.run.cmd([self.bin_path] + args, **kwargs).stdout.decode("utf-8")


def configure_tld(zonename: str, delegations: List[Zone]) -> Zone:
    templates = isctest.template.TemplateEngine(".")
    alg = default_algorithm()
    keygen = CmdHelper("KEYGEN", f"-q -a {alg.number} -b {alg.bits} -L 3600")
    signer = CmdHelper("SIGNER", "-S -g")

    isctest.log.info(f"create {zonename} zone with delegations and sign")

    for zone in delegations:
        shutil.copy(f"{zone.ns.name}/dsset-{zone.name}.", "ns2/")

    ksk_name = keygen(f"-f KSK {zonename}", cwd="ns2").strip()
    zsk_name = keygen(f"{zonename}", cwd="ns2").strip()
    ksk = isctest.kasp.Key(ksk_name, keydir="ns2")
    zsk = isctest.kasp.Key(zsk_name, keydir="ns2")
    dnskeys = [ksk.dnskey, zsk.dnskey]

    template = "template.db.j2.manual"
    outfile = f"{zonename}.db"
    tdata = {
        "fqdn": f"{zonename}.",
        "delegations": delegations,
        "dnskeys": dnskeys,
    }
    templates.render(f"ns2/{outfile}", tdata, template=f"ns2/{template}")
    signer(f"-P -x -O full -o {zonename} -f {outfile}.signed {outfile}", cwd="ns2")

    return Zone(zonename, f"{outfile}.signed", Nameserver("ns2", "10.53.0.2"))


def configure_root(delegations: List[Zone]) -> TrustAnchor:
    templates = isctest.template.TemplateEngine(".")
    alg = default_algorithm()
    keygen = CmdHelper("KEYGEN", f"-q -a {alg.number} -b {alg.bits} -L 3600")
    signer = CmdHelper("SIGNER", "-S -g")

    zonename = "."
    isctest.log.info("create root zone with delegations and sign")

    for zone in delegations:
        shutil.copy(f"{zone.ns.name}/dsset-{zone.name}.", "ns1/")

    ksk_name = keygen(f"-f KSK {zonename}", cwd="ns1").strip()
    zsk_name = keygen(f"{zonename}", cwd="ns1").strip()
    ksk = isctest.kasp.Key(ksk_name, keydir="ns1")
    zsk = isctest.kasp.Key(zsk_name, keydir="ns1")
    dnskeys = [ksk.dnskey, zsk.dnskey]

    template = "root.db.j2.manual"
    infile = "root.db.in"
    outfile = "root.db.signed"
    tdata = {
        "fdqn": f"{zonename}.",
        "delegations": delegations,
        "dnskeys": dnskeys,
    }
    templates.render(f"ns1/{infile}", tdata, template=f"ns1/{template}")
    signer(f"-P -x -O full -o {zonename} -f {outfile} {infile}", cwd="ns1")

    return ksk.into_ta("static-ds")
