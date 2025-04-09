import pytest

import dns.name

from dns.zone import Zone
from hypothesis import given, settings

from isctest.hypothesis.strategies import zones, dns_names


@settings(deadline=None, max_examples=1000)
@given(zones(auth_ip="10.0.53.1"))
def test_generated_zones(servers, zone: Zone):
    pass


@settings(deadline=None, max_examples=10000)
@given(dns_names(suffix=dns.name.from_text("example.com.")))
def test_generated_names(servers, name: dns.name.Name):
    pass
