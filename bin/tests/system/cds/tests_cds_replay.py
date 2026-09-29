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

from pathlib import Path

import os
import shutil
import time

from cds.common import EXTRA_ARTIFACTS
from isctest.algorithms import Algorithm
from isctest.kasp import SettimeOptions, private_type_record
from isctest.run import EnvCmd

import isctest

pytestmark = EXTRA_ARTIFACTS

DOMAIN = "example.test"
NOW = int(time.time())

DIR = {}
DIR["T0"] = "t0"
DIR["T1"] = "t1"
DIR["T2"] = "t2"

TIME = {}
TIME["T0"] = NOW - 1800
TIME["T1"] = NOW - 1200
TIME["T2"] = NOW - 600


def render_and_sign_zone(
    zonename: str, keys: list[str], timestamp, extra_options: str = ""
):
    keydir = DIR[timestamp]
    dnskeys = []
    privaterrs = []
    for key_name in keys:
        key = isctest.kasp.Key(key_name, keydir=keydir)
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
    templates.render(f"{keydir}/{outfile}", tdata, template=f"{keydir}/{template}")

    inception = TIME[timestamp]

    signer = EnvCmd(
        "SIGNER", f"-S -g -z -x -G cds:sha-256 -s {inception} -e now+2w -O full"
    )
    signer(f"{extra_options} -o {zonename} -f {outfile}.signed {outfile}", cwd=keydir)


def extract_from_signedzone(rrtype: str, signed_zone: str) -> list[str]:
    """Extract the RRset and its RRSIGs from a signed zone file."""
    records = []

    filepath = Path(signed_zone)

    with open(signed_zone, "r", encoding="utf-8") as file:
        for line in file:
            # Ignore comments and empty lines.
            line = line.strip()
            if not line or line.startswith(";"):
                continue

            # Remove inline comments.
            line = line.split(";", 1)[0].rstrip()

            fields = line.split()

            # RR:
            if fields[3] == rrtype:
                records.append(line)
                continue

            # RRSIG:
            if fields[3] == "RRSIG" and fields[4] == rrtype:
                records.append(line)

    if not records:
        raise ValueError(f"no {rrtype} RRset found in {signed_zone}")

    return records


def set_mtime(path: Path, timestamp: int) -> None:
    os.utime(path, (timestamp, timestamp))


def get_mtime(path: Path) -> int:
    return int(path.stat().st_mtime)


def setkeytimes(key_name: str, keydir: str, options: SettimeOptions) -> None:
    key = isctest.kasp.Key(key_name, keydir=keydir)
    key.settime(options)


def cds(
    child_file: str, dsset_file: str, domain: str, raise_on_exception=True
) -> (str, str):
    cds_cmd = EnvCmd("CDS", "-i")
    return cds_cmd(
        f"-f {child_file} -d {dsset_file} {domain}",
        raise_on_exception=raise_on_exception,
    )


def copy_keyfiles(filename: str, from_dir: str, to_dir: str) -> None:
    for ext in ["key", "private", "state"]:
        shutil.copyfile(f"{from_dir}/{filename}.{ext}", f"{to_dir}/{filename}.{ext}")


def test_cds_replay():
    """
    Regression test for dnssec-cds replay protection.

    dnssec-cds -i derives its replay watermark from the dsset- file mtime.
    matching_sigs() updates the global oldestsig from every verified RRset.
    Consequently, an old DNSKEY RRSIG can prevent a newer CDS signature
    from advancing the replay watermark.

    Scenario:

    T0 = 2026-07-09 01:00:00
    T1 = 2026-07-09 02:00:00
    T2 = 2026-07-09 03:00:00

    Run 1:
        DNSKEY RRSIG = T0
        CDS RRSIG    = T2

        Expected:
            DS set is updated to the T2 DS set.
            dsset mtime must advance to T2.

    Run 2:
        DNSKEY RRSIG = T0
        CDS RRSIG    = T1   (replay)

        Expected:
            replayed T1 CDS must be rejected.
            DS set must remain the T2 DS set.

    This test is intended to fail against the vulnerable implementation.
    """
    zone = DOMAIN
    alg = Algorithm.default()
    keygen = EnvCmd("KEYGEN", f"-q -a {alg.number} -b {alg.bits} -L 3600")
    key_names = {}

    # Key generation.
    timings = SettimeOptions(
        P="now-7d",
        P_sync="now-7d",
        A="now-7d",
    )
    # T0.
    key_names["T0"] = keygen(f"-f KSK {zone}", cwd="t0").out.strip()
    setkeytimes(key_names["T0"], DIR["T0"], timings)
    # T2.
    key_names["T2"] = keygen(f"-f KSK {zone}", cwd="t2").out.strip()
    shutil.copyfile(
        f"{DIR['T2']}/{key_names['T2']}.key", f"{DIR['T0']}/{key_names['T2']}.key"
    )
    shutil.copyfile(
        f"{DIR['T2']}/{key_names['T2']}.private",
        f"{DIR['T0']}/{key_names['T2']}.private",
    )
    setkeytimes(key_names["T2"], DIR["T2"], timings)

    # Signing.

    # T0: A DNSKEY RRset with the predecessor key and successor key present, signed with both.
    copy_keyfiles(key_names["T2"], DIR["T2"], DIR["T0"])
    render_and_sign_zone(zone, [key_names["T0"], key_names["T2"]], "T0")

    # T1: A CDS RRset with just the predecessor key present, signed with the predecessor key, at T1.
    copy_keyfiles(key_names["T0"], DIR["T0"], DIR["T1"])
    render_and_sign_zone(zone, [key_names["T0"]], "T1")

    # A CDS RRset with just the successor key present, signed with both, at T2.
    # Remove predecessor CDS when signing the zone at T2 via key timings.
    copy_keyfiles(key_names["T0"], DIR["T0"], DIR["T2"])
    timings2 = SettimeOptions(
        P="now-14d",
        P_sync="now-14d",
        A="now-14d",
        D_sync="now-7d",
    )
    setkeytimes(key_names["T0"], DIR["T2"], timings2)

    render_and_sign_zone(zone, [key_names["T0"], key_names["T2"]], "T2")

    # Actual start of test.
    dsset_file = f"t0/dsset-{zone}."
    dsset = Path(dsset_file)
    set_mtime(dsset, TIME["T0"])

    # Initial dsset mtime was T0.
    mtime = get_mtime(dsset)
    assert mtime == TIME["T0"]

    # The first dnssec-cds -i run accepted a child file containing DNSKEY RRSIGs
    # signed at T0 and a CDS RRset signed at T2; the dsset content changed to
    # the new DS set but the mtime remained T0.
    dnskey_t0 = extract_from_signedzone("DNSKEY", f"{DIR['T0']}/{zone}.db.signed")
    cds_t2 = extract_from_signedzone("CDS", f"{DIR['T2']}/{zone}.db.signed")

    child_file = "child_file.dnskey_t0.cds_t2"
    with open(child_file, "w", encoding="utf-8") as file:
        for rr in dnskey_t0:
            file.write(f"{rr}\n")
        for rr in cds_t2:
            file.write(f"{rr}\n")

    cds(child_file, dsset_file, zone)

    mtime = get_mtime(dsset)
    assert mtime >= TIME["T2"], (
        "dnssec-cds did not advance the dsset replay watermark to the "
        "newly accepted CDS signature\n"
        f"expected mtime >= {TIME['T2']}, got {mtime}"
    )

    t2_dsset = dsset.read_bytes()

    # A second dnssec-cds -i run accepted a child file containing the same
    # DNSKEY RRSIGs from T0 and an older CDS RRset signed at T1; the dsset
    # content changed back to the previous DS set.
    cds_t1 = extract_from_signedzone("CDS", f"{DIR['T1']}/{zone}.db.signed")

    child_file = "child_file.dnskey_t0.cds_t1"
    with open(child_file, "w", encoding="utf-8") as file:
        for rr in dnskey_t0:
            file.write(f"{rr}\n")
        for rr in cds_t1:
            file.write(f"{rr}\n")

    output = cds(child_file, dsset_file, zone, raise_on_exception=False)
    assert (
        f"dnssec-cds: fatal: could not validate child DNSKEY RRset for example.test"
        in output.err
    )

    # The watermark must also remain at T2 (or later).
    mtime = get_mtime(dsset)
    assert mtime >= TIME["T2"], (
        "dsset replay watermark regressed after the rejected replay\n"
        f"expected mtime >= {TIME['T2']}, got {mtime}"
    )
    assert dsset.read_bytes() == t2_dsset
