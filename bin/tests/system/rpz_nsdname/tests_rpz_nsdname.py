import isctest


def test_rpz_nsdname(ns3):
    msg = isctest.query.create("a.example.", "A")
    response = isctest.query.udp(msg, ns3.ip)
    isctest.check.nxdomain(response)

    msg = isctest.query.create("b.example.", "A")
    response = isctest.query.udp(msg, ns3.ip)
    isctest.check.nxdomain(response)
