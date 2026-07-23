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

from dns import rcode, rdataclass, rdatatype, rrset

from isctest.asyncserver import (
    AsyncDnsServer,
    IgnoreAllQueries,
    QnameQtypeHandler,
    StaticResponseHandler,
)


# Answer only to the A query, then ignore the other queries:
# this leave the time to the resolver to get answer/validate
# the answer from hoster1. NS and cancel the validation for
# this A answer.
# In principle, we could re-use the zone generated from the
# main test file, but it is simpler that way for just a
# single name.
class AnswerAHandler(QnameQtypeHandler, StaticResponseHandler):
    qnames = ["ns-tld.hoster2."]
    qtypes = [rdatatype.A]
    answer = [
        rrset.from_text("ns-tld.hoster2.", 300, rdataclass.IN, rdatatype.A, "10.53.0.3")
    ]


def main() -> None:
    server = AsyncDnsServer(default_rcode=rcode.NOERROR, default_aa=True)
    server.install_response_handlers(AnswerAHandler(), IgnoreAllQueries())
    server.run()


if __name__ == "__main__":
    main()
