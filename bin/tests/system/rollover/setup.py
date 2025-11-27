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
