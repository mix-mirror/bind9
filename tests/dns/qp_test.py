#!/usr/bin/python3

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


"""
Example property-based test for dns_name_ API.
"""

import pytest

# in FIPs mode md5 fails so we need 4.41.2 or later which does not use md5
try:
    import hashlib

    hashlib.md5(b"1234")
    pytest.importorskip("hypothesis")
except ValueError:
    pytest.importorskip("hypothesis", minversion="4.41.2")

from hypothesis import assume, example, event, given
from hypothesis.stateful import Bundle, RuleBasedStateMachine, rule, precondition
import hypothesis

pytest.importorskip("dns", minversion="2.0.0")
import dns.name

from strategies import dns_names, composite

from _qp_test_cffi import ffi
from _qp_test_cffi import lib as isclibs

NULL = ffi.NULL

MCTXP = ffi.new("isc_mem_t **")
isclibs.isc__mem_create(MCTXP)
MCTX = MCTXP[0]


def event(*args):
   pass


#def print(*args):
#    pass


@composite
def subdomains(draw, named_bundle):
    parent = draw(named_bundle)
    # the parent name has less then two bytes left, no way to add a subdomain to it
    if len(parent) + sum(map(len, parent)) > 253:
        return parent
    subdomain = draw(dns_names(suffix=parent))
    return subdomain


class ISCName:
    """
    dns_name_t instance with a private fixed buffer

    Make sure Python keeps reference to this object as long
    as it can be referenced from the C side.
    """

    def __init__(self, initval=None):
        self.fixedname = ffi.new("dns_fixedname_t *")
        self.cobj = isclibs.dns_fixedname_initname(self.fixedname)
        # self.cctx = ffi.new("dns_compress_t *")
        # self.dctx = ffi.new("dns_decompress_t *")
        self.formatbuf = ffi.new("char[1024]")  # DNS_NAME_FORMATSIZE

        if initval is None:
            return

        if isinstance(initval, dns.name.Name):
            initval = str(initval)
        if isinstance(initval, str):
            assert (
                isclibs.dns_name_fromstring(
                    self.cobj, initval.encode("ascii"), NULL, 0, NULL
                )
                == 0
            )
            return
        raise NotImplementedError(type(initval))

    def cformat(self):
        isclibs.dns_name_format(self.cobj, self.formatbuf, len(self.formatbuf))
        return ffi.string(self.formatbuf).decode("ascii")

    def pyname(self):
        return dns.name.from_text(self.cformat())


@given(pyname_source=dns_names(suffix=dns.name.root))
def test_fromname_toname_roundtrip(pyname_source: dns.name.Name) -> None:
    """
    name to/from qpkey must not change the name
    """
    iscname_source = ISCName(pyname_source)
    assert pyname_source == iscname_source.pyname()

    qpkey = ffi.new("dns_qpkey_t *")
    qpkeysize = isclibs.dns_qpkey_fromname(qpkey[0], iscname_source.cobj)

    iscname_target = ISCName()
    isclibs.dns_qpkey_toname(qpkey[0], qpkeysize, iscname_target.cobj)

    pyname_target = iscname_target.pyname()
    assert pyname_source == pyname_target


class QPChain:
    def __init__(self, testcase):
        self.testcase = testcase
        self.iter_generation = testcase.generation
        self.qp = testcase.qp

        self.cchain = ffi.new("dns_qpchain_t *")
        # print(id(self), isclibs.dns_qpiter_init)
        isclibs.dns_qpchain_init(self.qp, self.cchain)

    def length(self):
        ret = isclibs.dns_qpchain_length(self.cchain)
        print(self, 'length', ret)
        return ret

    def print(self):
        print('C chain structure print out', self)
        for chainidx in range(self.length()):
            got_iscname, got_pval_r, _got_ival_r = self.node(chainidx)
            print('idx', chainidx, got_iscname.pyname())

    def check(self, pylookupname: dns.name.Name):
        print('check chain for lookup', pylookupname)
        print('model', sorted(self.testcase.model))
        chainidx = 0
        for idx in range(1, len(pylookupname) + 1):
            parentname = pylookupname.split(idx)[1]
            assert self.length() >= chainidx
            if parentname not in self.testcase.model:
                print(parentname, 'NOT present in model')
                continue
            print(parentname, 'IS present in model')
            got_iscname, got_pval_r, _got_ival_r = self.node(chainidx)
            print(self, 'idx', chainidx, got_iscname.pyname())
            assert parentname == got_iscname.pyname(), (
                "chain points to unexpected name, idx",
                idx,
            )
            assert self.testcase.model[parentname].cobj == got_pval_r

            chainidx += 1

        assert (
            self.length() == chainidx
        ), "chain length does not match"

    def node(self, level):
        iscname = ISCName()
        got_pval_r = ffi.new("void **")
        got_ival_r = ffi.new("uint32_t *")
        isclibs.dns_qpchain_node(
            self.cchain, level, iscname.cobj, got_pval_r, got_ival_r
        )
        print(
            id(self),
            "qpchain_node",
            "\n-> returned: ",
            iscname.pyname(),
            got_pval_r[0],
            got_ival_r[0],
        )
        return iscname, got_pval_r[0], got_ival_r[0]


class QPIterator:
    def __init__(self, testcase):
        self.testcase = testcase
        self.iter_generation = testcase.generation
        self.qp = testcase.qp

        self.citer = ffi.new("dns_qpiter_t *")
        # print(id(self), isclibs.dns_qpiter_init)
        isclibs.dns_qpiter_init(self.qp, self.citer)

        self.model = testcase.model.copy()
        self.sorted = sorted(self.model)
        self.position = None

    def set_to_predecessor(self, name: dns.name.Name):
        self.position = self._find_predecesor(name)

    def set_to_name(self, name: dns.name.Name):
        self.position = self.sorted.index(name)

    def _find_predecesor(self, lookup: dns.name.Name):
        """ridiculously ineffective method for finding closest predecesor of a given name"""
        print(self.sorted)
        for reversed_idx, present in enumerate(reversed(self.sorted)):
            print(present, "?? < ??", lookup)
            if present < lookup:
                print("yes!")
                idx = len(self.sorted) - 1 - reversed_idx
                print(
                    "_find_predecesor regular, idx",
                    len(self.sorted) - 1 - reversed_idx,
                    self.sorted[idx],
                )
                return idx
        print("_find_predecesor wraparound", len(self.sorted) - 1)
        if len(self.sorted) > 0:
            # predecessor is BEFORE the first existing name, wrap around to the last name
            return len(self.sorted) - 1
        else:
            # predecessor does not exist at all - an empty QP
            return None

    def _step(self, cfunc):
        iscname = ISCName()
        got_pval_r = ffi.new("void **")
        got_ival_r = ffi.new("uint32_t *")
        got_ret = cfunc(self.citer, iscname.cobj, got_pval_r, got_ival_r)
        print(
            id(self),
            "_step",
            cfunc,
            "\n-> returned: ",
            got_ret,
            iscname.pyname(),
            got_pval_r[0],
            got_ival_r[0],
        )
        return got_ret, iscname, got_pval_r[0], got_ival_r[0]

    def _check_return_values(self, got_iscname, got_pval_r, _got_ival_r):
        assert self.position is not None, "usage error in test script"
        exp_pyname = self.sorted[self.position]
        exp_iscname = self.model[exp_pyname]
        assert exp_pyname == got_iscname.pyname()
        assert exp_iscname.cobj == got_pval_r

    def is_valid(self):
        """Check if QP this iterator referenced is supposed to be still valid"""
        return self.iter_generation == self.testcase.generation

    def next_(self):
        got_ret, got_iscname, got_pval_r, got_ival_r = self._step(
            isclibs.dns_qpiter_next
        )
        if len(self.model) == 0 or self.position == len(self.model) - 1:
            assert got_ret == isclibs.ISC_R_NOMORE
            self.position = None
        else:
            assert got_ret == isclibs.ISC_R_SUCCESS
            if self.position is None:
                self.position = 0
            else:
                self.position += 1
            self._check_return_values(got_iscname, got_pval_r, got_ival_r)
        return got_ret, got_iscname, got_pval_r, got_ival_r

    def prev(self):
        got_ret, got_iscname, got_pval_r, got_ival_r = self._step(
            isclibs.dns_qpiter_prev
        )
        if len(self.model) == 0 or self.position == 0:
            assert got_ret == isclibs.ISC_R_NOMORE
            self.position = None
        else:
            assert got_ret == isclibs.ISC_R_SUCCESS
            if self.position is None:
                self.position = len(self.model) - 1
            else:
                self.position -= 1
            self._check_return_values(got_iscname, got_pval_r, got_ival_r)
        return got_ret, got_iscname, got_pval_r, got_ival_r

    def current(self):
        got_ret, got_iscname, got_pval_r, got_ival_r = self._step(
            isclibs.dns_qpiter_current
        )

        if self.position is None:
            assert got_ret == isclibs.ISC_R_FAILURE
            return

        assert got_ret == isclibs.ISC_R_SUCCESS
        self._check_return_values(got_iscname, got_pval_r, got_ival_r)
        return got_ret, got_iscname, got_pval_r, got_ival_r


class BareQPTest(RuleBasedStateMachine):
    def __init__(self):
        super().__init__()
        self.generation = 0
        print("\n\nTEST RESTART FROM SCRATCH, GENERATION", self.generation)

        self.qpptr = ffi.new("dns_qp_t **")
        isclibs.dns_qp_create(MCTX, ffi.addressof(isclibs.qp_methods), NULL, self.qpptr)
        self.qp = self.qpptr[0]

        self.model = {}
        self.iter_ = QPIterator(self)
        self.chain = QPChain(self)

    names = Bundle("names")
    iterators = Bundle("iterators")

    def invalidate_refs(self):
        """Mark current QP as changed - iterators which depend on unchanged state are now invalid"""
        self.generation += 1
        return  # TODO

        self.iter_ = QPIterator(self)
        self.chain = QPChain(self)
        print("GENERATION ", self.generation)

    @rule(target=names, pyname=dns_names())
    def add_random(self, pyname):
        event("ADD random")
        return self._add(pyname)

    @precondition(lambda self: len(self.model) > 0)
    @rule(target=names, pyname=subdomains(names))
    def add_subdomain(self, pyname):
        event("ADD subdomain")
        return self._add(pyname)

    def _add(self, pyname):
        iscname = ISCName(pyname)

        ret = isclibs.dns_qp_insert(self.qp, iscname.cobj, 0)
        print("insert", pyname, ret)
        event("INSERT", ret)
        if pyname not in self.model:
            assert ret == isclibs.ISC_R_SUCCESS
            self.model[pyname] = iscname
        else:
            assert ret == isclibs.ISC_R_EXISTS

        self.invalidate_refs()
        return pyname

    @rule(pyname=names)
    def delete(self, pyname):
        print("DELETENAME", pyname)
        exists = pyname in self.model

        iscname = ISCName(pyname)

        pval = ffi.new("void **")
        ret = isclibs.dns_qp_deletename(self.qp, iscname.cobj, pval, NULL)
        event("DELETENAME", ret)
        if exists:
            assert ret == isclibs.ISC_R_SUCCESS
            assert pval[0] == self.model[pyname].cobj
            del self.model[pyname]
        else:
            assert ret == isclibs.ISC_R_NOTFOUND
        self.invalidate_refs()

    def iter_init(self):
        event("init")
        self.iter_ = QPIterator(self)

    @precondition(lambda self: self.iter_.is_valid())
    @rule()
    def iter_next(self):
        if not self.iter_.is_valid():
            event("iter invalid")
            return

        event("next", self.iter_.position)
        self.iter_.next_()

    @precondition(lambda self: self.iter_.is_valid())
    @rule()
    def iter_prev(self):
        if not self.iter_.is_valid():
            event("iter invalid")
            return

        event("prev", self.iter_.position)
        self.iter_.prev()

    @precondition(lambda self: self.iter_.is_valid())
    @rule()
    def iter_current(self):
        if not self.iter_.is_valid():
            event("iter invalid")
            return

        event("current")
        self.iter_.current()

    @rule(pylookupname=dns_names())
    def lookup_random(self, pylookupname):
        return self._lookup(pylookupname)

    @rule(pylookupname=names)
    def lookup_known(self, pylookupname):
        return self._lookup(pylookupname)

    @precondition(lambda self: len(self.model) > 0)
    @rule(pylookupname=subdomains(names))
    def lookup_subdomain(self, pylookupname):
        return self._lookup(pylookupname)

    def _lookup(self, pylookupname):
        outiter = QPIterator(self)
        lookupname = ISCName(pylookupname)
        foundname = ISCName()
        ret = isclibs.dns_qp_lookup(
            self.qp,
            lookupname.cobj,
            foundname.cobj,
            outiter.citer,
            self.chain.cchain,
            NULL,
            NULL,
        )
        print("LOOKUP", ret, pylookupname)
        event("LOOKUP", ret)

        # verify that no unepected parent name exists in our model
        if ret == isclibs.ISC_R_NOTFOUND:
            # no parent can be present, not even the root
            common_labels = 0
            outiter.set_to_predecessor(pylookupname)
        elif ret == isclibs.DNS_R_PARTIALMATCH:
            assert (
                foundname.pyname() < pylookupname
            ), "foundname is not a subdomain of looked up name"
            common_labels = len(foundname.pyname())
            outiter.set_to_predecessor(pylookupname)
        elif ret == isclibs.ISC_R_SUCCESS:
            # exact match!
            assert pylookupname == foundname.pyname()
            common_labels = len(pylookupname)
            outiter.set_to_name(pylookupname)
        else:
            raise NotImplementedError(ret)

        for splitidx in range(len(pylookupname), common_labels, -1):
            parentname = pylookupname.split(splitidx)[1]
            assert (
                parentname not in self.model
            ), "found parent node which reportedly does not exist"

        self.chain.print()
        # verify chain produced by lookup
        self.chain.check(pylookupname)

        # iterator must point to the foundname or predecessor
        outiter.current()

        # overwrite the previous iterator with the one produced by lookup()
        # this should allow the state machine to excercise iteration after lookup
        self.iter_ = outiter

    @rule()
    def values_agree_forward(self):
        """Iterate through all values and check ordering"""
        tmp_iter = QPIterator(self)
        event("values_agree_forward", len(tmp_iter.model))

        qp_count = 0
        while (got_ret := tmp_iter.next_()[0]) == isclibs.ISC_R_SUCCESS:
            qp_count += 1

        assert qp_count == len(tmp_iter.model)

    @rule()
    def values_agree_backwards(self):
        """Iterate through all values and check ordering"""
        tmp_iter = QPIterator(self)
        event("values_agree_backwards", len(tmp_iter.model))

        qp_count = 0
        while (got_ret := tmp_iter.prev()[0]) == isclibs.ISC_R_SUCCESS:
            qp_count += 1

        assert qp_count == len(tmp_iter.model)


TestTrees = BareQPTest.TestCase
TestTrees.settings = hypothesis.settings(
    max_examples=1000,
    deadline=None,
    # stateful_step_count=10000,
    # suppress_health_check=[hypothesis.HealthCheck.large_base_example, hypothesis.HealthCheck.too_slow]
)

# Or just run with pytest's unittest support
if __name__ == "__main__":
    state = BareQPTest()
    state.add_random(dns.name.from_text(r"a."))
    state.add_random(dns.name.from_text(r"d.b.a."))
    state.add_random(dns.name.from_text(r"z.d.b.a."))
    state.lookup_subdomain(dns.name.from_text(r"f.c.b.a."))
    # unittest.main()
