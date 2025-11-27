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


def fake_lifetime(keys: List[str]):
    """
    Fake lifetime of old algorithm keys.
    """
    for key in keys:
        with open(f"ns3/{key}.state", "a") as statefile:
            statefile.write("Lifetime: 0\n")


def set_key_relationship(key1: str, key2: str):
    """
    Set in the key state files the Predecessor/Successor fields.
    """
    predecessor = isctest.kasp.Key(key1, keydir="ns3")
    successor = isctest.kasp.Key(key2, keydir="ns3")

    with open(f"ns3/{key1}.state", "a", encoding="utf-8") as statefile:
        statefile.write(f"Successor: {successor.tag}\n")

    with open(f"ns3/{key2}.state", "a", encoding="utf-8") as statefile:
        statefile.write(f"Predecessor: {predecessor.tag}\n")


def render_and_sign_zone(zonename: str, keys: List[str], extra_options: str = ""):
    dnskeys = []
    privaterrs = []
    for key_name in keys:
        key = isctest.kasp.Key(key_name, keydir="ns3")
        privaterr = private_type_record(zonename, key)
        dnskeys.append(key.dnskey)
        privaterrs.append(privaterr)

    outfile = f"{zonename}.db"
    templates = isctest.template.TemplateEngine(".")
    template = "template.db.j2.manual"
    tdata = {
        "fqdn": f"{zonename}.",
        "dnskeys": dnskeys,
        "privaterrs": privaterrs,
    }
    templates.render(f"ns3/{outfile}", tdata, template=f"ns3/{template}")

    signer = CmdHelper("SIGNER", "-S -g -x -s now-1h -e now+2w -O raw")
    signer(f"{extra_options} -o {zonename} -f {outfile}.signed {outfile}", cwd="ns3")


def configure_algo_csk(tld: str, policy: str, reconfig: bool = False) -> List[Zone]:
    # The zones at csk-algorithm-roll.$tld represent the various steps
    # of a CSK algorithm rollover.
    zones = []
    zone = f"csk-algorithm-roll.{tld}"
    keygen = CmdHelper("KEYGEN", f"-k {policy}")
    settime = CmdHelper("SETTIME", "-s")

    # Step 1:
    # Introduce the first key. This will immediately be active.
    zonename = f"step1.{zone}"
    zones.append(Zone(zonename, f"{zonename}.db", Nameserver("ns3", "10.53.0.3")))
    isctest.log.info(f"setup {zonename}")
    TactN = "now-7d"
    TsbmN = "now-161h"
    csktimes = f"-P {TactN} -A {TactN}"
    # Key generation.
    csk_name = keygen(f"-l csk1.conf {csktimes} {zonename}", cwd="ns3").strip()
    settime(
        f"-g OMNIPRESENT -k OMNIPRESENT {TactN} -r OMNIPRESENT {TactN} -z OMNIPRESENT {TactN} -d OMNIPRESENT {TactN} {csk_name}",
        cwd="ns3",
    )
    # Signing.
    render_and_sign_zone(zonename, [csk_name], extra_options="-z")

    if reconfig:
        # Step 2:
        # After the publication interval has passed the DNSKEY is OMNIPRESENT.
        zonename = f"step2.{zone}"
        zones.append(Zone(zonename, f"{zonename}.db", Nameserver("ns3", "10.53.0.3")))
        isctest.log.info(f"setup {zonename}")
        # The time passed since the new algorithm keys have been introduced is 3 hours.
        TpubN1 = "now-3h"
        csktimes = f"-P {TactN} -A {TactN} -P sync {TsbmN} -I now"
        newtimes = f"-P {TpubN1} -A {TpubN1}"
        # Key generation.
        csk1_name = keygen(f"-l csk1.conf {csktimes} {zonename}", cwd="ns3").strip()
        csk2_name = keygen(f"-l csk2.conf {newtimes} {zonename}", cwd="ns3").strip()
        settime(
            f"-g HIDDEN -k OMNIPRESENT {TactN} -r OMNIPRESENT {TactN} -z OMNIPRESENT {TactN} -d OMNIPRESENT {TactN} {csk1_name}",
            cwd="ns3",
        )
        settime(
            f"-g OMNIPRESENT -k RUMOURED {TpubN1} -r RUMOURED {TpubN1} -z RUMOURED {TpubN1} -d HIDDEN {TpubN1} {csk2_name}",
            cwd="ns3",
        )
        # Signing.
        render_and_sign_zone(zonename, [csk1_name, csk2_name], extra_options="-z")

        # Step 3:
        # The zone signatures are also OMNIPRESENT.
        zonename = f"step3.{zone}"
        zones.append(Zone(zonename, f"{zonename}.db", Nameserver("ns3", "10.53.0.3")))
        isctest.log.info(f"setup {zonename}")
        # The time passed since the new algorithm keys have been introduced is 7 hours.
        TpubN1 = "now-7h"
        TsbmN1 = "now"
        csktimes = f"-P {TactN} -A {TactN}  -P sync {TsbmN} -I {TsbmN1}"
        newtimes = f"-P {TpubN1} -A {TpubN1} -P sync {TsbmN1}"
        # Key generation.
        csk1_name = keygen(f"-l csk1.conf {csktimes} {zonename}", cwd="ns3").strip()
        csk2_name = keygen(f"-l csk2.conf {newtimes} {zonename}", cwd="ns3").strip()
        settime(
            f"-g HIDDEN -k OMNIPRESENT {TactN} -r OMNIPRESENT {TactN} -z OMNIPRESENT {TactN} -d OMNIPRESENT {TactN} {csk1_name}",
            cwd="ns3",
        )
        settime(
            f"-g OMNIPRESENT -k OMNIPRESENT {TpubN1} -r OMNIPRESENT {TpubN1} -z RUMOURED {TpubN1} -d HIDDEN {TpubN1} {csk2_name}",
            cwd="ns3",
        )
        # Signing.
        render_and_sign_zone(zonename, [csk1_name, csk2_name], extra_options="-z")

        # Step 4:
        # The DS is swapped and can become OMNIPRESENT.
        zonename = f"step4.{zone}"
        zones.append(Zone(zonename, f"{zonename}.db", Nameserver("ns3", "10.53.0.3")))
        isctest.log.info(f"setup {zonename}")
        # The time passed since the DS has been swapped is 3 hours.
        TpubN1 = "now-10h"
        TsbmN1 = "now-3h"
        csktimes = f"-P {TactN} -A {TactN}  -P sync {TsbmN} -I {TsbmN1}"
        newtimes = f"-P {TpubN1} -A {TpubN1} -P sync {TsbmN1}"
        # Key generation.
        csk1_name = keygen(f"-l csk1.conf {csktimes} {zonename}", cwd="ns3").strip()
        csk2_name = keygen(f"-l csk2.conf {newtimes} {zonename}", cwd="ns3").strip()
        settime(
            f"-g HIDDEN -k OMNIPRESENT {TactN} -r OMNIPRESENT {TactN} -z OMNIPRESENT {TsbmN1} -d UNRETENTIVE {TsbmN1} -D ds {TsbmN1} {csk1_name}",
            cwd="ns3",
        )
        settime(
            f"-g OMNIPRESENT -k OMNIPRESENT {TpubN1} -r OMNIPRESENT {TpubN1} -z OMNIPRESENT {TsbmN1} -d RUMOURED {TsbmN1} -P ds {TsbmN1} {csk2_name}",
            cwd="ns3",
        )
        # Signing.
        render_and_sign_zone(zonename, [csk1_name, csk2_name], extra_options="-z")

        # Step 5:
        # The DNSKEY is removed long enough to be HIDDEN.
        zonename = f"step5.{zone}"
        zones.append(Zone(zonename, f"{zonename}.db", Nameserver("ns3", "10.53.0.3")))
        isctest.log.info(f"setup {zonename}")
        # The time passed since the DNSKEY has been removed is 2 hours.
        TpubN1 = "now-12h"
        TsbmN1 = "now-5h"
        csktimes = f"-P {TactN} -A {TactN} -P sync {TsbmN} -I {TsbmN1}"
        newtimes = f"-P {TpubN1} -A {TpubN1} -P sync {TsbmN1}"
        # Key generation.
        csk1_name = keygen(f"-l csk1.conf {csktimes} {zonename}", cwd="ns3").strip()
        csk2_name = keygen(f"-l csk2.conf {newtimes} {zonename}", cwd="ns3").strip()
        settime(
            f"-g HIDDEN -k UNRETENTIVE {TactN} -r UNRETENTIVE {TactN} -z UNRETENTIVE {TsbmN1} -d HIDDEN {TsbmN1} {csk1_name}",
            cwd="ns3",
        )
        settime(
            f"-g OMNIPRESENT -k OMNIPRESENT {TpubN1} -r OMNIPRESENT {TpubN1} -z OMNIPRESENT {TsbmN1} -d OMNIPRESENT {TsbmN1} {csk2_name}",
            cwd="ns3",
        )
        # Signing.
        render_and_sign_zone(zonename, [csk1_name, csk2_name], extra_options="-z")

        # Step 6:
        # The RRSIGs have been removed long enough to be HIDDEN.
        zonename = f"step6.{zone}"
        zones.append(Zone(zonename, f"{zonename}.db", Nameserver("ns3", "10.53.0.3")))
        isctest.log.info(f"setup {zonename}")
        # Additional time passed: 7h.
        TpubN1 = "now-19h"
        TsbmN1 = "now-12h"
        csktimes = f"-P {TactN}  -A {TactN}  -P sync {TsbmN} -I {TsbmN1}"
        newtimes = f"-P {TpubN1} -A {TpubN1} -P sync {TsbmN1}"
        # Key generation.
        csk1_name = keygen(f"-l csk1.conf {csktimes} {zonename}", cwd="ns3").strip()
        csk2_name = keygen(f"-l csk2.conf {newtimes} {zonename}", cwd="ns3").strip()
        settime(
            f"-g HIDDEN -k HIDDEN {TactN} -r UNRETENTIVE {TactN} -z UNRETENTIVE {TactN} -d HIDDEN {TsbmN1} {csk1_name}",
            cwd="ns3",
        )
        settime(
            f"-g OMNIPRESENT -k OMNIPRESENT {TpubN1} -r OMNIPRESENT {TpubN1} -z OMNIPRESENT {TsbmN1} -d OMNIPRESENT {TsbmN1} {csk2_name}",
            cwd="ns3",
        )
        # Signing.
        render_and_sign_zone(zonename, [csk1_name, csk2_name], extra_options="-z")

    return zones


def configure_algo_ksk_zsk(tld: str, reconfig: bool = False) -> List[Zone]:
    # The zones at algorithm-roll.$tld represent the various steps of a ZSK/KSK
    # algorithm rollover.
    zones = []
    zone = f"algorithm-roll.{tld}"
    keygen = CmdHelper("KEYGEN", "-L 3600")
    settime = CmdHelper("SETTIME", "-s")

    # Step 1:
    # Introduce the first key. This will immediately be active.
    zonename = f"step1.{zone}"
    zones.append(Zone(zonename, f"{zonename}.db", Nameserver("ns3", "10.53.0.3")))
    isctest.log.info(f"setup {zonename}")
    TactN = "now-7d"
    TsbmN = "now-161h"
    keytimes = f"-P {TactN} -A {TactN}"
    # Key generation.
    ksk_name = keygen(f"-a RSASHA256 -f KSK {keytimes} {zonename}", cwd="ns3").strip()
    zsk_name = keygen(f"-a RSASHA256 {keytimes} {zonename}", cwd="ns3").strip()
    settime(
        f"-g OMNIPRESENT -k OMNIPRESENT {TactN} -r OMNIPRESENT {TactN} -d OMNIPRESENT {TactN} {ksk_name}",
        cwd="ns3",
    )
    settime(
        f"-g OMNIPRESENT -k OMNIPRESENT {TactN} -z OMNIPRESENT {TactN} {zsk_name}",
        cwd="ns3",
    )
    # Signing.
    render_and_sign_zone(zonename, [ksk_name, zsk_name])

    if reconfig:
        # Step 2:
        # After the publication interval has passed the DNSKEY is OMNIPRESENT.
        zonename = f"step2.{zone}"
        zones.append(Zone(zonename, f"{zonename}.db", Nameserver("ns3", "10.53.0.3")))
        isctest.log.info(f"setup {zonename}")
        # The time passed since the new algorithm keys have been introduced is 3 hours.
        # Tsbm(N+1) = TpubN1 + Ipub = now + TTLsig + Dprp = now - 3h + 6h + 1h = now + 4h
        TpubN1 = "now-3h"
        TsbmN1 = "now+4h"
        ksk1times = f"-P {TactN}  -A {TactN}  -P sync {TsbmN} -I {TsbmN1}"
        zsk1times = f"-P {TactN}  -A {TactN}  -I {TsbmN1}"
        ksk2times = f"-P {TpubN1} -A {TpubN1} -P sync {TsbmN1}"
        zsk2times = f"-P {TpubN1} -A {TpubN1}"
        # Key generation.
        ksk1_name = keygen(
            f"-a RSASHA256 -f KSK {ksk1times} {zonename}", cwd="ns3"
        ).strip()
        zsk1_name = keygen(f"-a RSASHA256 {zsk1times} {zonename}", cwd="ns3").strip()
        ksk2_name = keygen(
            f"-a ECDSA256 -f KSK {ksk2times} {zonename}", cwd="ns3"
        ).strip()
        zsk2_name = keygen(f"-a ECDSA256 {zsk2times} {zonename}", cwd="ns3").strip()
        settime(
            f"-g HIDDEN -k OMNIPRESENT {TactN} -r OMNIPRESENT {TactN} -d OMNIPRESENT {TactN} {ksk1_name}",
            cwd="ns3",
        )
        settime(
            f"-g HIDDEN -k OMNIPRESENT {TactN} -z OMNIPRESENT {TactN} {zsk1_name}",
            cwd="ns3",
        )
        settime(
            f"-g OMNIPRESENT -k RUMOURED {TpubN1} -r RUMOURED {TpubN1} -d HIDDEN {TpubN1} {ksk2_name}",
            cwd="ns3",
        )
        settime(
            f"-g OMNIPRESENT -k RUMOURED {TpubN1} -z RUMOURED {TpubN1} {zsk2_name}",
            cwd="ns3",
        )
        # Signing.
        fake_lifetime([ksk1_name, zsk1_name])
        render_and_sign_zone(zonename, [ksk1_name, zsk1_name, ksk2_name, zsk2_name])

        # Step 3:
        # The zone signatures are also OMNIPRESENT.
        zonename = f"step3.{zone}"
        zones.append(Zone(zonename, f"{zonename}.db", Nameserver("ns3", "10.53.0.3")))
        isctest.log.info(f"setup {zonename}")
        # The time passed since the new algorithm keys have been introduced is 7 hours.
        TpubN1 = "now-7h"
        TsbmN1 = "now"
        ksk1times = f"-P {TactN} -A {TactN} -P sync {TsbmN} -I {TsbmN1}"
        zsk1times = f"-P {TactN} -A {TactN} -I {TsbmN1}"
        ksk2times = f"-P {TpubN1} -A {TpubN1} -P sync {TsbmN1}"
        zsk2times = f"-P {TpubN1} -A {TpubN1}"
        # Key generation.
        ksk1_name = keygen(
            f"-a RSASHA256 -f KSK {ksk1times} {zonename}", cwd="ns3"
        ).strip()
        zsk1_name = keygen(f"-a RSASHA256 {zsk1times} {zonename}", cwd="ns3").strip()
        ksk2_name = keygen(
            f"-a ECDSA256 -f KSK {ksk2times} {zonename}", cwd="ns3"
        ).strip()
        zsk2_name = keygen(f"-a ECDSA256 {zsk2times} {zonename}", cwd="ns3").strip()
        settime(
            f"-g HIDDEN -k OMNIPRESENT {TactN} -r OMNIPRESENT {TactN} -d OMNIPRESENT {TactN} {ksk1_name}",
            cwd="ns3",
        )
        settime(
            f"-g HIDDEN -k OMNIPRESENT {TactN} -z OMNIPRESENT {TactN} {zsk1_name}",
            cwd="ns3",
        )
        settime(
            f"-g OMNIPRESENT -k OMNIPRESENT {TpubN1} -r OMNIPRESENT {TpubN1} -d HIDDEN {TpubN1} {ksk2_name}",
            cwd="ns3",
        )
        settime(
            f"-g OMNIPRESENT -k OMNIPRESENT {TpubN1} -z RUMOURED {TpubN1} {zsk2_name}",
            cwd="ns3",
        )
        # Signing.
        fake_lifetime([ksk1_name, zsk1_name])
        render_and_sign_zone(zonename, [ksk1_name, zsk1_name, ksk2_name, zsk2_name])

        # Step 4:
        # The DS is swapped and can become OMNIPRESENT.
        zonename = f"step4.{zone}"
        zones.append(Zone(zonename, f"{zonename}.db", Nameserver("ns3", "10.53.0.3")))
        isctest.log.info(f"setup {zonename}")
        # The time passed since the DS has been swapped is 3 hours.
        TpubN1 = "now-10h"
        TsbmN1 = "now-3h"
        ksk1times = f"-P {TactN} -A {TactN} -P sync {TsbmN} -I {TsbmN1}"
        zsk1times = f"-P {TactN} -A {TactN} -I {TsbmN1}"
        ksk2times = f"-P {TpubN1} -A {TpubN1} -P sync {TsbmN1}"
        zsk2times = f"-P {TpubN1} -A {TpubN1}"
        # Key generation.
        ksk1_name = keygen(
            f"-a RSASHA256 -f KSK {ksk1times} {zonename}", cwd="ns3"
        ).strip()
        zsk1_name = keygen(f"-a RSASHA256 {zsk1times} {zonename}", cwd="ns3").strip()
        ksk2_name = keygen(
            f"-a ECDSA256 -f KSK {ksk2times} {zonename}", cwd="ns3"
        ).strip()
        zsk2_name = keygen(f"-a ECDSA256 {zsk2times} {zonename}", cwd="ns3").strip()
        settime(
            f"-g HIDDEN -k OMNIPRESENT {TactN} -r OMNIPRESENT {TactN} -d UNRETENTIVE {TsbmN1} -D ds {TsbmN1} {ksk1_name}",
            cwd="ns3",
        )
        settime(
            f"-g HIDDEN -k OMNIPRESENT {TactN} -z OMNIPRESENT {TactN} {zsk1_name}",
            cwd="ns3",
        )
        settime(
            f"-g OMNIPRESENT -k OMNIPRESENT {TpubN1} -r OMNIPRESENT {TpubN1} -d RUMOURED {TsbmN1} -P ds {TsbmN1} {ksk2_name}",
            cwd="ns3",
        )
        settime(
            f"-g OMNIPRESENT -k OMNIPRESENT {TpubN1} -z RUMOURED {TpubN1} {zsk2_name}",
            cwd="ns3",
        )
        # Signing.
        fake_lifetime([ksk1_name, zsk1_name])
        render_and_sign_zone(zonename, [ksk1_name, zsk1_name, ksk2_name, zsk2_name])

        # Step 5:
        # The DNSKEY is removed long enough to be HIDDEN.
        zonename = f"step5.{zone}"
        zones.append(Zone(zonename, f"{zonename}.db", Nameserver("ns3", "10.53.0.3")))
        isctest.log.info(f"setup {zonename}")
        # The time passed since the DNSKEY has been removed is 2 hours.
        TpubN1 = "now-12h"
        TsbmN1 = "now-5h"
        ksk1times = f"-P {TactN} -A {TactN} -P sync {TsbmN} -I {TsbmN1}"
        zsk1times = f"-P {TactN} -A {TactN} -I {TsbmN1}"
        ksk2times = f"-P {TpubN1} -A {TpubN1} -P sync {TsbmN1}"
        zsk2times = f"-P {TpubN1} -A {TpubN1}"
        # Key generation.
        ksk1_name = keygen(
            f"-a RSASHA256 -f KSK {ksk1times} {zonename}", cwd="ns3"
        ).strip()
        zsk1_name = keygen(f"-a RSASHA256 {zsk1times} {zonename}", cwd="ns3").strip()
        ksk2_name = keygen(
            f"-a ECDSA256 -f KSK {ksk2times} {zonename}", cwd="ns3"
        ).strip()
        zsk2_name = keygen(f"-a ECDSA256 {zsk2times} {zonename}", cwd="ns3").strip()
        settime(
            f"-g HIDDEN -k UNRETENTIVE {TsbmN1} -r UNRETENTIVE {TsbmN1} -d HIDDEN {TsbmN1} {ksk1_name}",
            cwd="ns3",
        )
        settime(
            f"-g HIDDEN -k UNRETENTIVE {TsbmN1} -z UNRETENTIVE {TsbmN1} {zsk1_name}",
            cwd="ns3",
        )
        settime(
            f"-g OMNIPRESENT -k OMNIPRESENT {TpubN1} -r OMNIPRESENT {TpubN1} -d OMNIPRESENT {TsbmN1} {ksk2_name}",
            cwd="ns3",
        )
        settime(
            f"-g OMNIPRESENT -k OMNIPRESENT {TpubN1} -z RUMOURED {TpubN1} {zsk2_name}",
            cwd="ns3",
        )
        # Signing.
        fake_lifetime([ksk1_name, zsk1_name])
        render_and_sign_zone(zonename, [ksk1_name, zsk1_name, ksk2_name, zsk2_name])

        # Step 6:
        # The RRSIGs have been removed long enough to be HIDDEN.
        zonename = f"step6.{zone}"
        zones.append(Zone(zonename, f"{zonename}.db", Nameserver("ns3", "10.53.0.3")))
        isctest.log.info(f"setup {zonename}")
        # Additional time passed: 7h.
        TpubN1 = "now-19h"
        TsbmN1 = "now-12h"
        ksk1times = f"-P {TactN} -A {TactN} -P sync {TsbmN} -I {TsbmN1}"
        zsk1times = f"-P {TactN} -A {TactN} -I {TsbmN1}"
        ksk2times = f"-P {TpubN1} -A {TpubN1} -P sync {TsbmN1}"
        zsk2times = f"-P {TpubN1} -A {TpubN1}"
        ksk1_name = keygen(
            f"-a RSASHA256 -f KSK {ksk1times} {zonename}", cwd="ns3"
        ).strip()
        zsk1_name = keygen(f"-a RSASHA256 {zsk1times} {zonename}", cwd="ns3").strip()
        ksk2_name = keygen(
            f"-a ECDSA256 -f KSK {ksk2times} {zonename}", cwd="ns3"
        ).strip()
        zsk2_name = keygen(f"-a ECDSA256 {zsk2times} {zonename}", cwd="ns3").strip()
        settime(
            f"-g HIDDEN -k HIDDEN {TsbmN1} -r UNRETENTIVE {TsbmN1} -d HIDDEN {TsbmN1} {ksk1_name}",
            cwd="ns3",
        )
        settime(
            f"-g HIDDEN -k HIDDEN {TsbmN1} -z UNRETENTIVE {TsbmN1} {zsk1_name}",
            cwd="ns3",
        )
        settime(
            f"-g OMNIPRESENT -k OMNIPRESENT {TpubN1} -r OMNIPRESENT {TpubN1} -d OMNIPRESENT {TsbmN1} {ksk2_name}",
            cwd="ns3",
        )
        settime(
            f"-g OMNIPRESENT -k OMNIPRESENT {TpubN1} -z RUMOURED {TpubN1} {zsk2_name}",
            cwd="ns3",
        )
        # Signing.
        fake_lifetime([ksk1_name, zsk1_name])
        render_and_sign_zone(zonename, [ksk1_name, zsk1_name, ksk2_name, zsk2_name])

    return zones


def configure_cskroll1(tld: str, policy: str) -> List[Zone]:
    # The zones at csk-roll1.$tld represent the various steps of a CSK rollover
    # (which is essentially a ZSK Pre-Publication / KSK Double-KSK rollover).
    zones = []
    zone = f"csk-roll1.{tld}"
    keygen = CmdHelper("KEYGEN", f"-k {policy} -l kasp.conf")
    settime = CmdHelper("SETTIME", "-s")

    # Step 1:
    # Introduce the first key. This will immediately be active.
    zonename = f"step1.{zone}"
    zones.append(Zone(zonename, f"{zonename}.db", Nameserver("ns3", "10.53.0.3")))
    isctest.log.info(f"setup {zonename}")
    TactN = "now-7d"
    keytimes = f"-P {TactN} -A {TactN}"
    # Key generation.
    csk_name = keygen(f"{keytimes} {zonename}", cwd="ns3").strip()
    settime(
        f"-g OMNIPRESENT -k OMNIPRESENT {TactN} -r OMNIPRESENT {TactN} -z OMNIPRESENT {TactN} -d OMNIPRESENT {TactN} {csk_name}",
        cwd="ns3",
    )
    # Signing.
    render_and_sign_zone(zonename, [csk_name], extra_options="-z -G cdnskey,cds:sha384")

    # Step 2:
    # It is time to introduce the new CSK.
    zonename = f"step2.{zone}"
    zones.append(Zone(zonename, f"{zonename}.db", Nameserver("ns3", "10.53.0.3")))
    isctest.log.info(f"setup {zonename}")
    # According to RFC 7583:
    # KSK: Tpub(N+1) <= Tact(N) + Lksk - IpubC
    # ZSK: Tpub(N+1) <= Tact(N) + Lzsk - Ipub
    # IpubC = DprpC + TTLkey (+publish-safety)
    # Ipub  = IpubC
    # Lcsk = Lksk = Lzsk
    #
    # Lcsk:           6mo (186d, 4464h)
    # Dreg:           N/A
    # DprpC:          1h
    # TTLkey:         1h
    # publish-safety: 1h
    # Ipub:           3h
    #
    # Tact(N) = now - Lcsk + Ipub = now - 186d + 3h
    #         = now - 4464h + 3h  = now - 4461h
    TactN = "now-4461h"
    keytimes = f"-P {TactN} -A {TactN}"
    # Key generation.
    csk_name = keygen(f"{keytimes} {zonename}", cwd="ns3").strip()
    settime(
        f"-g OMNIPRESENT -k OMNIPRESENT {TactN} -r OMNIPRESENT {TactN} -z OMNIPRESENT {TactN} -d OMNIPRESENT {TactN} {csk_name}",
        cwd="ns3",
    )
    # Signing.
    render_and_sign_zone(zonename, [csk_name], extra_options="-z -G cdnskey,cds:sha384")

    # Step 3:
    # It is time to submit the DS and to roll signatures.
    zonename = f"step3.{zone}"
    zones.append(Zone(zonename, f"{zonename}.db", Nameserver("ns3", "10.53.0.3")))
    isctest.log.info(f"setup {zonename}")
    # According to RFC 7583:
    #
    # Tsbm(N+1) >= Trdy(N+1)
    # KSK: Tact(N+1) = Tsbm(N+1)
    # ZSK: Tact(N+1) = Tpub(N+1) + Ipub = Tsbm(N+1)
    # KSK: Iret  = DprpP + TTLds (+retire-safety)
    # ZSK: IretZ = Dsgn + Dprp + TTLsig (+retire-safety)
    #
    # Lcsk:           186d
    # Dprp:           1h
    # DprpP:          1h
    # Dreg:           N/A
    # Dsgn:           25d
    # TTLds:          1h
    # TTLsig:         1d
    # retire-safety:  2h
    # Iret:           4h
    # IretZ:          26d3h
    # Ipub:           3h
    #
    # Tpub(N)   = now - Lcsk = now - 186d
    # Tact(N)   = now - Lcsk + Dprp + TTLsig = now - 4439h
    # Tret(N)   = now
    # Trem(N)   = now + IretZ = now + 26d3h = now + 627h
    # Tpub(N+1) = now - Ipub = now - 3h
    # Tact(N+1) = Tret(N)
    # Tret(N+1) = now + Lcsk = now + 186d = now + 186d
    # Trem(N+1) = now + Lcsk + IretZ = now + 186d + 26d3h =
    #           = now + 5091h
    TpubN = "now-186d"
    TactN = "now-4439h"
    TretN = "now"
    TremN = "now+627h"
    TpubN1 = "now-3h"
    TactN1 = TretN
    TretN1 = "now+186d"
    TremN1 = "now+5091h"
    keytimes = (
        f"-P {TpubN} -P sync {TactN} -A {TpubN} -I {TretN} -D {TremN} -D sync {TactN1}"
    )
    newtimes = f"-P {TpubN1} -P sync {TactN1} -A {TactN1} -I {TretN1} -D {TremN1}"
    # Key generation.
    csk1_name = keygen(f"{keytimes} {zonename}", cwd="ns3").strip()
    csk2_name = keygen(f"{newtimes} {zonename}", cwd="ns3").strip()
    settime(
        f"-g HIDDEN -k OMNIPRESENT {TactN} -r OMNIPRESENT {TactN} -z OMNIPRESENT {TactN} -d OMNIPRESENT {TactN} {csk1_name}",
        cwd="ns3",
    )
    settime(
        f"-g OMNIPRESENT -k RUMOURED {TpubN1} -r RUMOURED {TpubN1} -z HIDDEN {TpubN1} -d HIDDEN {TpubN1} {csk2_name}",
        cwd="ns3",
    )
    # Set key rollover relationship.
    set_key_relationship(csk1_name, csk2_name)
    # Signing.
    render_and_sign_zone(
        zonename, [csk1_name, csk2_name], extra_options="-z -G cdnskey,cds:sha384"
    )

    # Step 4:
    # Some time later all the ZRRSIG records should be from the new CSK, and the
    # DS should be swapped.  The ZRRSIG records are all replaced after IretZ
    # (which is 26d3h).  The DS is swapped after Iret (which is 4h).
    # In other words, the DS is swapped before all zone signatures are replaced.
    zonename = f"step4.{zone}"
    zones.append(Zone(zonename, f"{zonename}.db", Nameserver("ns3", "10.53.0.3")))
    isctest.log.info(f"setup {zonename}")
    # According to RFC 7583:
    # Trem(N)    = Tret(N) - Iret + IretZ
    # now       = Tsbm(N+1) + Iret
    #
    # Lcsk:   186d
    # Iret:   4h
    # IretZ:  26d3h
    #
    # Tpub(N)   = now - Iret - Lcsk = now - 4h - 186d = now - 4468h
    # Tret(N)   = now - Iret = now - 4h = now - 4h
    # Trem(N)   = now - Iret + IretZ = now - 4h + 26d3h
    #           = now + 623h
    # Tpub(N+1) = now - Iret - IpubC = now - 4h - 3h = now - 7h
    # Tact(N+1) = Tret(N)
    # Tret(N+1) = now - Iret + Lcsk = now - 4h + 186d = now + 4460h
    # Trem(N+1) = now - Iret + Lcsk + IretZ = now - 4h + 186d + 26d3h
    #           = now + 5087h
    TpubN = "now-4468h"
    TactN = "now-4443h"
    TretN = "now-4h"
    TremN = "now+623h"
    TpubN1 = "now-7h"
    TactN1 = TretN
    TretN1 = "now+4460h"
    TremN1 = "now+5087h"
    keytimes = (
        f"-P {TpubN} -P sync {TactN} -A {TpubN} -I {TretN} -D {TremN} -D sync {TactN1}"
    )
    newtimes = f"-P {TpubN1} -P sync {TactN1} -A {TactN1} -I {TretN1} -D {TremN1}"
    # Key generation.
    csk1_name = keygen(f"{keytimes} {zonename}", cwd="ns3").strip()
    csk2_name = keygen(f"{newtimes} {zonename}", cwd="ns3").strip()
    settime(
        f"-g HIDDEN -k OMNIPRESENT {TactN} -r OMNIPRESENT {TactN} -z UNRETENTIVE {TactN1} -d UNRETENTIVE {TactN1} -D ds {TactN1} {csk1_name}",
        cwd="ns3",
    )
    settime(
        f"-g OMNIPRESENT -k OMNIPRESENT {TactN1} -r OMNIPRESENT {TactN1} -z RUMOURED {TactN1} -d RUMOURED {TactN1} -P ds {TactN1} {csk2_name}",
        cwd="ns3",
    )
    # Set key rollover relationship.
    set_key_relationship(csk1_name, csk2_name)
    # Signing.
    render_and_sign_zone(
        zonename, [csk1_name, csk2_name], extra_options="-z -G cdnskey,cds:sha384"
    )

    # Step 5:
    # After the DS is swapped in step 4, also the KRRSIG records can be removed.
    # At this time these have all become hidden.
    zonename = f"step5.{zone}"
    zones.append(Zone(zonename, f"{zonename}.db", Nameserver("ns3", "10.53.0.3")))
    isctest.log.info(f"setup {zonename}")
    # Subtract DNSKEY TTL plus zone propagation delay from all the times (2h).
    TpubN = "now-4470h"
    TactN = "now-4445h"
    TretN = "now-6h"
    TremN = "now+621h"
    TpubN1 = "now-9h"
    TactN1 = TretN
    TretN1 = "now+4458h"
    TremN1 = "now+5085h"
    keytimes = (
        f"-P {TpubN} -P sync {TactN} -A {TpubN} -I {TretN} -D {TremN} -D sync {TactN1}"
    )
    newtimes = f"-P {TpubN1} -P sync {TactN1} -A {TactN1} -I {TretN1} -D {TremN1}"
    # Key generation.
    csk1_name = keygen(f"{keytimes} {zonename}", cwd="ns3").strip()
    csk2_name = keygen(f"{newtimes} {zonename}", cwd="ns3").strip()
    settime(
        f"-g HIDDEN -k OMNIPRESENT {TactN} -r UNRETENTIVE now-2h -z UNRETENTIVE {TactN1} -d HIDDEN now-2h {csk1_name}",
        cwd="ns3",
    )
    settime(
        f"-g OMNIPRESENT -k OMNIPRESENT {TactN1} -r OMNIPRESENT {TactN1} -z RUMOURED {TactN1} -d OMNIPRESENT now-2h {csk2_name}",
        cwd="ns3",
    )
    # Set key rollover relationship.
    set_key_relationship(csk1_name, csk2_name)
    # Signing.
    render_and_sign_zone(
        zonename, [csk1_name, csk2_name], extra_options="-z -G cdnskey,cds:sha384"
    )

    # Step 6:
    # After the retire interval has passed the predecessor DNSKEY can be
    # removed from the zone.
    zonename = f"step6.{zone}"
    zones.append(Zone(zonename, f"{zonename}.db", Nameserver("ns3", "10.53.0.3")))
    isctest.log.info(f"setup {zonename}")
    # According to RFC 7583:
    # Trem(N) = Tret(N) + IretZ
    # Tret(N) = Tact(N) + Lcsk
    #
    # Lcsk:   186d
    # Iret:   4h
    # IretZ:  26d3h
    #
    # Tpub(N)   = now - IretZ - Lcsk = now - 627h - 186d
    #           = now - 627h - 4464h = now - 5091h
    # Tact(N)   = now - 627h - 186d
    # Tret(N)   = now - IretZ = now - 627h
    # Trem(N)   = now
    # Tpub(N+1) = now - IretZ - Ipub = now - 627h - 3h = now - 630h
    # Tact(N+1) = Tret(N)
    # Tret(N+1) = now - IretZ + Lcsk = now - 627h + 186d = now + 3837h
    # Trem(N+1) = now + Lcsk = now + 186d
    TpubN = "now-5091h"
    TactN = "now-5066h"
    TretN = "now-627h"
    TremN = "now"
    TpubN1 = "now-630h"
    TactN1 = TretN
    TretN1 = "now+3837h"
    TremN1 = "now+186d"
    keytimes = (
        f"-P {TpubN} -P sync {TactN} -A {TpubN} -I {TretN} -D {TremN} -D sync {TactN1}"
    )
    newtimes = f"-P {TpubN1} -P sync {TactN1} -A {TactN1} -I {TretN1} -D {TremN1}"
    # Key generation.
    csk1_name = keygen(f"{keytimes} {zonename}", cwd="ns3").strip()
    csk2_name = keygen(f"{newtimes} {zonename}", cwd="ns3").strip()
    settime(
        f"-g HIDDEN -k OMNIPRESENT {TactN} -r HIDDEN {TremN} -z UNRETENTIVE {TactN1} -d HIDDEN {TremN} {csk1_name}",
        cwd="ns3",
    )
    settime(
        f"-g OMNIPRESENT -k OMNIPRESENT {TactN1} -r OMNIPRESENT {TactN1} -z RUMOURED {TactN1} -d OMNIPRESENT {TremN} {csk2_name}",
        cwd="ns3",
    )
    # Set key rollover relationship.
    set_key_relationship(csk1_name, csk2_name)
    # Signing.
    render_and_sign_zone(
        zonename, [csk1_name, csk2_name], extra_options="-z -G cdnskey,cds:sha384"
    )

    # Step 7:
    # Some time later the predecessor DNSKEY enters the HIDDEN state.
    zonename = f"step7.{zone}"
    zones.append(Zone(zonename, f"{zonename}.db", Nameserver("ns3", "10.53.0.3")))
    isctest.log.info(f"setup {zonename}")
    # Subtract DNSKEY TTL plus zone propagation delay from all the times (2h).
    TpubN = "now-5093h"
    TactN = "now-5068h"
    TretN = "now-629h"
    TremN = "now-2h"
    TpubN1 = "now-632h"
    TactN1 = TretN
    TretN1 = "now+3835h"
    TremN1 = "now+4462h"
    keytimes = (
        f"-P {TpubN} -P sync {TactN} -A {TpubN} -I {TretN} -D {TremN} -D sync {TactN1}"
    )
    newtimes = f"-P {TpubN1} -P sync {TactN1} -A {TactN1} -I {TretN1} -D {TremN1}"
    # Key generation.
    csk1_name = keygen(f"{keytimes} {zonename}", cwd="ns3").strip()
    csk2_name = keygen(f"{newtimes} {zonename}", cwd="ns3").strip()
    settime(
        f"-g HIDDEN -k UNRETENTIVE {TremN} -r HIDDEN {TremN} -z HIDDEN {TactN1} -d HIDDEN {TremN} {csk1_name}",
        cwd="ns3",
    )
    settime(
        f"-g OMNIPRESENT -k OMNIPRESENT {TactN1} -r OMNIPRESENT {TactN1} -z OMNIPRESENT {TactN1} -d OMNIPRESENT {TactN1} {csk2_name}",
        cwd="ns3",
    )
    # Set key rollover relationship.
    set_key_relationship(csk1_name, csk2_name)
    # Signing.
    render_and_sign_zone(
        zonename, [csk1_name, csk2_name], extra_options="-z -G cdnskey,cds:sha384"
    )

    # Step 8:
    # The predecessor DNSKEY can be purged.
    zonename = f"step8.{zone}"
    zones.append(Zone(zonename, f"{zonename}.db", Nameserver("ns3", "10.53.0.3")))
    isctest.log.info(f"setup {zonename}")
    # Subtract purge-keys interval from all the times (1h).
    TpubN = "now-5094h"
    TactN = "now-5069h"
    TretN = "now-630h"
    TremN = "now-3h"
    TpubN1 = "now-633h"
    TactN1 = TretN
    TretN1 = "now+3834h"
    TremN1 = "now+4461h"
    keytimes = (
        f"-P {TpubN} -P sync {TactN} -A {TpubN} -I {TretN} -D {TremN} -D sync {TactN1}"
    )
    newtimes = f"-P {TpubN1} -P sync {TactN1} -A {TactN1} -I {TretN1} -D {TremN1}"
    # Key generation.
    csk1_name = keygen(f"{keytimes} {zonename}", cwd="ns3").strip()
    csk2_name = keygen(f"{newtimes} {zonename}", cwd="ns3").strip()
    settime(
        f"-g HIDDEN -k HIDDEN {TremN} -r HIDDEN {TremN} -z HIDDEN {TactN1} -d HIDDEN {TremN} {csk1_name}",
        cwd="ns3",
    )
    settime(
        f"-g OMNIPRESENT -k OMNIPRESENT {TactN1} -r OMNIPRESENT {TactN1} -z OMNIPRESENT {TactN1} -d OMNIPRESENT {TactN1} {csk2_name}",
        cwd="ns3",
    )
    # Set key rollover relationship.
    set_key_relationship(csk1_name, csk2_name)
    # Signing.
    render_and_sign_zone(
        zonename, [csk1_name, csk2_name], extra_options="-z -G cdnskey,cds:sha384"
    )

    return zones
