"""
Copyright (C) Internet Systems Consortium, Inc. ("ISC")

SPDX-License-Identifier: MPL-2.0

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0.  If a copy of the MPL was not distributed with this
file, you can obtain one at https://mozilla.org/MPL/2.0/.

See the COPYRIGHT file distributed with this work for additional
information regarding copyright ownership.
"""

import abc

import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from typing import AsyncGenerator, Sequence

from isctest.asyncserver import (
    ControllableAsyncDnsServer,
    DnsResponseSend,
    QueryContext,
    ResponseHandler,
    SwitchControlCommand,
)


def soa(serial: int, *, owner: str = "nil.") -> dns.rrset.RRset:
    return dns.rrset.from_text(
        owner,
        300,
        dns.rdataclass.IN,
        dns.rdatatype.SOA,
        f"ns.nil. root.nil. {serial} 300 300 604800 300",
    )


def ns() -> dns.rrset.RRset:
    return dns.rrset.from_text(
        "nil.",
        300,
        dns.rdataclass.IN,
        dns.rdatatype.NS,
        "ns.nil.",
    )


def a(label: str, *, third_octet: int = 0, last_octet: int) -> dns.rrset.RRset:
    return dns.rrset.from_text(
        f"{label}.nil.",
        60,
        dns.rdataclass.IN,
        dns.rdatatype.A,
        f"10.0.{third_octet}.{last_octet}",
    )


def txt(txt: str, *, label: str = "") -> dns.rrset.RRset:
    return dns.rrset.from_text(
        "nil." if not label else f"{label}.nil.",
        300,
        dns.rdataclass.IN,
        dns.rdatatype.TXT,
        f'"{txt}"',
    )


class SoaHandler(ResponseHandler):
    def __init__(self, serial: int):
        self._serial = serial

    def match(self, qctx: QueryContext):
        return qctx.qtype == dns.rdatatype.SOA

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        qctx.response.answer.append(soa(self._serial))
        yield DnsResponseSend(qctx.response)


class AxfrHandler(ResponseHandler):
    @property
    @abc.abstractmethod
    def answers(self) -> Sequence[Sequence[dns.rrset.RRset]]:
        """
        Answer sections of response packets sent in response to
        AXFR queries.
        """
        raise NotImplementedError

    def match(self, qctx: QueryContext):
        return qctx.qtype == dns.rdatatype.AXFR

    async def get_responses(self, qctx: QueryContext):
        for answer in self.answers:
            response = qctx.prepare_new_response()
            for rrset in answer:
                response.answer.append(rrset)
            yield DnsResponseSend(response)


class IxfrHandler(ResponseHandler):
    @property
    @abc.abstractmethod
    def answer(self) -> Sequence[dns.rrset.RRset]:
        """
        Answer section of a response packet sent in response to
        IXFR queries.
        """
        raise NotImplementedError

    def match(self, qctx: QueryContext):
        return qctx.qtype == dns.rdatatype.IXFR

    async def get_responses(self, qctx: QueryContext):
        for rrset in self.answer:
            qctx.response.answer.append(rrset)
        yield DnsResponseSend(qctx.response)


class InitialAfxrHandler(AxfrHandler):
    answers = (
        (soa(1),),
        (
            ns(),
            txt("initial AXFR"),
            a("a", last_octet=61),
            a("b", last_octet=62),
        ),
        (soa(1),),
    )


class SuccessfulIfxrHandler(IxfrHandler):
    answer = (
        soa(3),
        soa(1),
        a("a", last_octet=61),
        txt("initial AXFR"),
        soa(2),
        txt("successful IXFR"),
        a("a", third_octet=1, last_octet=61),
        soa(2),
        soa(3),
        soa(3),
    )


class NotExactIxfrHandler(IxfrHandler):
    answer = (
        soa(4),
        soa(3),
        txt("delete-nonexistent-txt-record"),
        soa(4),
        txt("this-txt-record-would-be-added"),
        soa(4),
    )


class FallbackNotExactAxfrHandler(AxfrHandler):
    answers = (
        (soa(3),),
        (
            ns(),
            txt("fallback AXFR"),
        ),
        (soa(3),),
    )


class TooManyRecordsIxfrHandler(IxfrHandler):
    answer = (
        soa(4),
        soa(3),
        soa(4),
        txt("text 1"),
        txt("text 2"),
        txt("text 3"),
        txt("text 4"),
        txt("text 5"),
        txt("text 6: causing too many records"),
        soa(4),
    )


class FallbackTooManyRecordsAxfrHandler(AxfrHandler):
    answers = (
        (
            soa(3),
            ns(),
            txt("fallback AXFR on too many records"),
        ),
        (soa(3),),
    )


class BadSoaOwnerIxfrHandler(IxfrHandler):
    answer = (
        soa(4),
        soa(3),
        soa(4, owner="bad-owner."),
        txt("serial 4, malformed IXFR", label="test"),
        soa(4),
    )


class FallbackBadSoaOwnerAxfrHandler(AxfrHandler):
    answers = (
        (soa(4),),
        (
            ns(),
            txt("serial 4, fallback AXFR", label="test"),
        ),
        (soa(4),),
    )


def main() -> None:
    server = ControllableAsyncDnsServer(
        default_aa=True, default_rcode=dns.rcode.NOERROR
    )
    switch_command = SwitchControlCommand(
        {
            "initial_axfr": (
                SoaHandler(1),
                InitialAfxrHandler(),
            ),
            "successful_ixfr": (
                SoaHandler(3),
                SuccessfulIfxrHandler(),
            ),
            "not_exact": (
                SoaHandler(4),
                NotExactIxfrHandler(),
                FallbackNotExactAxfrHandler(),
            ),
            "too_many_records": (
                SoaHandler(4),
                TooManyRecordsIxfrHandler(),
                FallbackTooManyRecordsAxfrHandler(),
            ),
            "bad_soa_owner": (
                SoaHandler(4),
                BadSoaOwnerIxfrHandler(),
                FallbackBadSoaOwnerAxfrHandler(),
            ),
        }
    )
    server.install_control_command(switch_command)
    server.run()


if __name__ == "__main__":
    main()
