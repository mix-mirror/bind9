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

import dns.dnssec
import dns.name
import dns.query
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.update
import dns.zone

from nsec3.common import NSEC3_MARK, NSEC3_SALTLEN, wait_for_nsec3param

import isctest

pytestmark = NSEC3_MARK

ZONE = "nsec3-rebuild.kasp"
FQDN = f"{ZONE}."
DELETED_NAME = f"zzzz.{FQDN}"

# Include the following zone when rendering named configs.
ZONES = {
    ZONE,
}


def bootstrap():
    return {
        "zones": ZONES,
    }


def _wait_for_rcode(server, qname, rdtype, rcode):
    query = isctest.query.create(qname, rdtype)

    def _matches():
        response = isctest.query.tcp(query, server.ip, attempts=1, timeout=3)
        return response.rcode() == rcode

    isctest.run.retry_with_timeout(
        _matches,
        timeout=10,
        msg=f"{qname} did not return {dns.rcode.to_text(rcode)} within 10s",
    )


def test_full_rebuild_ignores_names_deleted_after_snapshot(ns3, templates):
    isctest.kasp.wait_keymgr_done(ns3, ZONE)
    wait_for_nsec3param(ns3, ZONE, NSEC3_SALTLEN[ZONE].initial)

    # Fill the source tree so that zzzz remains ahead of the rebuild cursor
    # while the raw-to-secure inline update is being committed.  All names are
    # added in one transaction, so observing zzzz proves the whole update is
    # present in the secure zone.
    update = dns.update.UpdateMessage(ZONE)
    for number in range(300):
        update.add(f"name{number:03d}.{FQDN}", 300, "A", "10.0.0.1")
    update.add(DELETED_NAME, 300, "A", "10.0.0.1")
    ns3.nsupdate(update)
    _wait_for_rcode(ns3, DELETED_NAME, dns.rdatatype.A, dns.rcode.NOERROR)

    # Changing the NSEC3 parameters starts a full rebuild and creates the
    # persistent qpzone iterator snapshot.  Delete zzzz only after that
    # snapshot exists, but before its late position is visited.
    with ns3.watch_log_from_here() as watcher:
        data = {
            "reconfiged": True,
            "zones": ZONES,
        }
        templates.render(f"{ns3.identifier}/named-fips.conf", data)
        ns3.reconfigure()
        watcher.wait_for_line("zone_addnsec3chain(1,CREATE|OPTOUT,0,")

    update = dns.update.UpdateMessage(ZONE)
    update.delete(DELETED_NAME, dns.rdatatype.A)
    ns3.nsupdate(update)
    _wait_for_rcode(ns3, DELETED_NAME, dns.rdatatype.A, dns.rcode.NXDOMAIN)

    # The public NSEC3PARAM appears only after the new chain is complete.
    wait_for_nsec3param(ns3, ZONE, NSEC3_SALTLEN[ZONE].reconfig)

    query = isctest.query.create(FQDN, dns.rdatatype.NSEC3PARAM)
    response = isctest.query.tcp(query, ns3.ip)
    assert response.rcode() == dns.rcode.NOERROR
    params = [
        rdata
        for rrset in response.answer
        if rrset.match(
            dns.name.from_text(FQDN),
            dns.rdataclass.IN,
            dns.rdatatype.NSEC3PARAM,
            dns.rdatatype.NONE,
        )
        for rdata in rrset
    ]
    assert len(params) == 1

    param = params[0]
    deleted_hash = dns.dnssec.nsec3_hash(
        DELETED_NAME,
        salt=param.salt,
        iterations=param.iterations,
        algorithm=param.algorithm,
    )
    hashed_name = f"{deleted_hash}.{FQDN}"
    transfer = dns.zone.Zone(origin=FQDN, relativize=False)
    dns.query.inbound_xfr(
        where=ns3.ip,
        txn_manager=transfer,
        port=ns3.ports.dns,
        timeout=10,
        lifetime=10,
    )
    assert transfer.get_rdataset(hashed_name, dns.rdatatype.NSEC3) is None
