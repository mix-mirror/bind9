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

############################################################################
# ans.py: See README.anspy for details.
############################################################################

from __future__ import print_function
import os
import sys
import signal
import socket
import select
from datetime import datetime, timedelta
import functools

import dns, dns.message, dns.query
from dns.rdatatype import *
from dns.rdataclass import *
from dns.rcode import *
from dns.name import *


############################################################################
# Respond to a DNS query.
############################################################################
def create_response(msg):
    m = dns.message.from_wire(msg)
    qname = m.question[0].name.to_text()
    labels = qname.lower().split(".")
    domain = "example."
    ns = "ns2.example."

    # get qtype
    rrtype = m.question[0].rdtype
    typename = dns.rdatatype.to_text(rrtype)

    print("query: " + qname + "/" + typename + "/%04x/%04x" % (m.flags, m.ednsflags))

    # default answers, depending on QTYPE.
    # currently only A, AAAA, TXT and NS are supported.
    ttl = 86400
    additionalA = "10.53.0.2"
    additionalAAAA = "fd92:7065:b8e:ffff::2"
    if typename == "A":
        final = "10.53.0.2"
    elif typename == "AAAA":
        final = "fd92:7065:b8e:ffff::2"
    elif typename == "TXT":
        final = "Some\ text\ here"
    elif typename == "NS":
        final = "ns2.example."
    else:
        final = None

    # construct answer set.
    r = dns.message.make_response(m)
    answers = []
    auth = []
    add = []
    print("ednswith %s" % qname.endswith(".example."))
    if qname.endswith(".example."):
        r.set_rcode(NXDOMAIN)
        auth.append(dns.rrset.from_text(domain, ttl, IN, SOA, ". . 0 0 0 0 0"))
        r.flags |= dns.flags.AA
    elif qname != "example.":
        r.set_rcode(REFUSED)
    elif final != None:
        answers.append(dns.rrset.from_text(qname, ttl, IN, typename, final))
        if typename == "NS":
            add.append(dns.rrset.from_text(ns, ttl, IN, A, additionalA))
            add.append(dns.rrset.from_text(ns, ttl, IN, AAAA, additionalAAAA))
        r.flags |= dns.flags.AA
    else:
        auth.append(dns.rrset.from_text(qname, ttl, IN, SOA, ". . 1 0 0 0 0"))
        r.flags |= dns.flags.AA

    if len(answers):
        r.answer.append(answers[-1])
    if len(auth):
        r.authority.append(auth[-1])
    if len(add):
        r.additional.append(add[-1])
    # we copy reserved flags (violation of STD13)
    if m.flags & 0x40:
        r.flags |= 0x40
    # we copy all EDNS flags (violation of STD75)
    r.use_edns(ednsflags=m.ednsflags)
    return r.to_wire()


def sigterm(signum, frame):
    print("Shutting down now...")
    os.remove("ans.pid")
    running = False
    sys.exit(0)


############################################################################
# Main
#
# Set up responder and control channel, open the pid file, and start
# the main loop, listening for queries on the query channel or commands
# on the control channel and acting on them.
############################################################################
ip4 = "10.53.0.2"
ip6 = "fd92:7065:b8e:ffff::2"

try:
    port = int(os.environ["PORT"])
except:
    port = 5300

try:
    ctrlport = int(os.environ["EXTRAPORT1"])
except:
    ctrlport = 5300

query4_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
query4_socket.bind((ip4, port))

havev6 = True
try:
    query6_socket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        query6_socket.bind((ip6, port))
    except:
        query6_socket.close()
        havev6 = False
except:
    havev6 = False

ctrl_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ctrl_socket.bind((ip4, ctrlport))
ctrl_socket.listen(5)

signal.signal(signal.SIGTERM, sigterm)

f = open("ans.pid", "w")
pid = os.getpid()
print(pid, file=f)
f.close()

running = True

print("Listening on %s port %d" % (ip4, port))
if havev6:
    print("Listening on %s port %d" % (ip6, port))
print("Control channel on %s port %d" % (ip4, ctrlport))
print("Ctrl-c to quit")

if havev6:
    input = [query4_socket, query6_socket, ctrl_socket]
else:
    input = [query4_socket, ctrl_socket]

while running:
    try:
        inputready, outputready, exceptready = select.select(input, [], [])
    except select.error as e:
        break
    except socket.error as e:
        break
    except KeyboardInterrupt:
        break

    for s in inputready:
        if s == ctrl_socket:
            # Handle control channel input
            conn, addr = s.accept()
            print("Control channel connected")
            while True:
                msg = conn.recv(65535)
                if not msg:
                    break
                ctl_channel(msg)
            conn.close()
        if s == query4_socket or s == query6_socket:
            print("Query received on %s" % (ip4 if s == query4_socket else ip6))
            # Handle incoming queries
            msg = s.recvfrom(65535)
            rsp = create_response(msg[0])
            if rsp:
                s.sendto(rsp, msg[1])
    if not running:
        break
