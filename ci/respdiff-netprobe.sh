#!/usr/bin/env bash

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

# Probe which per-resolver source addressing schemes work on a CI runner.
#
# A packet capture of respdiff's upstream traffic is only useful if each
# packet can be attributed to one resolver instance. All instances share the
# runner's outbound address and pick random source ports, so this script
# tries the alternatives and records, for each, whether a query bound to the
# scheme's address reaches the internet and how it shows up in a capture:
#
#   lo-alias   address on lo, as bin/tests/system/ifconfig.sh creates them
#   dev-alias  extra /32 on the egress interface, outside its subnet
#   netns      resolver in its own network namespace behind a veth pair,
#              masqueraded by the container (needs CAP_NET_ADMIN and nft)
#
# Usage: respdiff-netprobe.sh [output-dir]
#
# Results land in the output directory (default ./netprobe): summary.txt plus
# per-probe dig output and captures. The exit code is always 0; the artifacts
# are the result.

set -u

if [ "$(id -u)" -ne 0 ]; then
  exec sudo "$0" "$@"
fi

out=${1:-netprobe}
mkdir -p "$out"
: >"$out/summary.txt"

# k.root-servers.net; answers ". NS" itself, so no resolver is involved.
root_server=193.0.14.129

# Namespace to run the probe queries in, empty for the root namespace.
query_ns=

log() {
  printf '%s\n' "$*" | tee -a "$out/summary.txt"
}

# query LABEL [dig options...]: ask the root server for ". NS" and record
# OK or FAIL in the summary.
query() {
  local label=$1
  shift
  local -a prefix=()
  if [ -n "$query_ns" ]; then
    prefix=(ip netns exec "$query_ns")
  fi
  if "${prefix[@]}" dig +time=3 +tries=1 +short "$@" @"$root_server" . NS \
    >"$out/dig-$label.txt" 2>&1 \
    && grep -q root-servers "$out/dig-$label.txt"; then
    log "RESULT $label: OK"
  else
    log "RESULT $label: FAIL ($(tr '\n' ' ' <"$out/dig-$label.txt" | cut -c1-120))"
  fi
}

# capture LABEL INTERFACE COMMAND...: run COMMAND while capturing port 53
# on INTERFACE, then append the first packets to the summary.
capture() {
  local label=$1 iface=$2
  shift 2
  tcpdump -i "$iface" -n -w "$out/$label.pcap" port 53 \
    2>"$out/$label.tcpdump.err" &
  local pid=$!
  sleep 1
  "$@"
  sleep 1
  kill -INT "$pid" 2>/dev/null
  wait "$pid" 2>/dev/null
  log "--- packets on $iface during $label:"
  tcpdump -nr "$out/$label.pcap" 2>/dev/null | head -6 | tee -a "$out/summary.txt"
}

cleanup() {
  ip address del 10.53.0.11/24 dev lo 2>/dev/null
  ip address del 10.54.0.1/32 dev "$egress_dev" 2>/dev/null
  nft delete table ip respdiff-probe 2>/dev/null
  ip netns del probe 2>/dev/null
}

log "== packages"
apt-get -y -q install dnsutils iproute2 nftables tcpdump >"$out/apt.log" 2>&1 \
  || log "apt-get failed, see apt.log"
for tool in dig ip nft tcpdump; do
  command -v "$tool" >/dev/null || log "missing: $tool"
done

log "== environment"
{
  id
  grep -i '^Cap' /proc/self/status
  ip -brief link
  ip -brief address
  ip route
  sysctl net.ipv4.ip_forward net.ipv4.ip_local_port_range
  nft list ruleset
} >"$out/environment.txt" 2>&1
egress_dev=$(ip route get "$root_server" | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -1)
egress_src=$(ip route get "$root_server" | sed -n 's/.* src \([^ ]*\).*/\1/p' | head -1)
log "egress interface: ${egress_dev:-?} source: ${egress_src:-?}"
log "$(grep CapEff /proc/self/status)"
trap cleanup EXIT

log "== baseline: shared runner address"
capture baseline any query baseline-udp
query baseline-tcp +tcp

log "== lo-alias: source 10.53.0.11 on lo, as ifconfig.sh creates them"
ip address add 10.53.0.11/24 dev lo
capture lo-alias any query lo-alias-udp -b 10.53.0.11
query lo-alias-tcp +tcp -b 10.53.0.11

log "== dev-alias: source 10.54.0.1/32 on $egress_dev"
ip address add 10.54.0.1/32 dev "$egress_dev"
capture dev-alias any query dev-alias-udp -b 10.54.0.1
query dev-alias-tcp +tcp -b 10.54.0.1

log "== netns: namespace behind a veth pair, masqueraded by the container"
{
  ip netns add probe
  ip link add veth-probe type veth peer name veth-inner
  ip link set veth-inner netns probe
  ip address add 10.54.1.1/24 dev veth-probe
  ip link set veth-probe up
  ip -n probe address add 10.54.1.2/24 dev veth-inner
  ip -n probe link set lo up
  ip -n probe link set veth-inner up
  ip -n probe route add default via 10.54.1.1
  sysctl -w net.ipv4.ip_forward=1
  nft add table ip respdiff-probe
  nft add chain ip respdiff-probe postrouting \
    '{ type nat hook postrouting priority srcnat; policy accept; }'
  nft add rule ip respdiff-probe postrouting \
    ip saddr 10.54.1.0/24 oifname "$egress_dev" masquerade
} >"$out/netns-setup.log" 2>&1 || log "netns setup failed, see netns-setup.log"
query_ns=probe
capture netns-veth veth-probe query netns-udp
capture netns-egress "$egress_dev" query netns-udp-egress
query netns-tcp +tcp
query_ns=

log "== done: see $out/"
