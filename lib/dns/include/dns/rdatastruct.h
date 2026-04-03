/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/*
 * Convenience header that includes all rdata structure definitions.
 * Headers are ordered by type code to satisfy inter-header dependencies.
 *
 * When adding a new rdata type, add its header in type-code order.
 */

#pragma once

#include <isc/sockaddr.h>

#include <dns/name.h>
#include <dns/types.h>

typedef struct dns_rdatacommon {
	dns_rdataclass_t rdclass;
	dns_rdatatype_t	 rdtype;
} dns_rdatacommon_t;

#define DNS_RDATACOMMON_INIT(_data, _rdtype, _rdclass) \
	do {                                           \
		(_data)->common.rdtype = (_rdtype);    \
		(_data)->common.rdclass = (_rdclass);  \
	} while (0)

/* clang-format off */
#include <dns/rdata/a_1.h>
#include <dns/rdata/ns_2.h>
#include <dns/rdata/md_3.h>
#include <dns/rdata/mf_4.h>
#include <dns/rdata/cname_5.h>
#include <dns/rdata/soa_6.h>
#include <dns/rdata/mb_7.h>
#include <dns/rdata/mg_8.h>
#include <dns/rdata/mr_9.h>
#include <dns/rdata/null_10.h>
#include <dns/rdata/wks_11.h>
#include <dns/rdata/ptr_12.h>
#include <dns/rdata/hinfo_13.h>
#include <dns/rdata/minfo_14.h>
#include <dns/rdata/mx_15.h>
#include <dns/rdata/txt_16.h>
#include <dns/rdata/rp_17.h>
#include <dns/rdata/afsdb_18.h>
#include <dns/rdata/x25_19.h>
#include <dns/rdata/isdn_20.h>
#include <dns/rdata/rt_21.h>
#include <dns/rdata/nsap_22.h>
#include <dns/rdata/nsap-ptr_23.h>
#include <dns/rdata/sig_24.h>
#include <dns/rdata/key_25.h>
#include <dns/rdata/px_26.h>
#include <dns/rdata/gpos_27.h>
#include <dns/rdata/aaaa_28.h>
#include <dns/rdata/loc_29.h>
#include <dns/rdata/nxt_30.h>
#include <dns/rdata/eid_31.h>
#include <dns/rdata/nimloc_32.h>
#include <dns/rdata/srv_33.h>
#include <dns/rdata/atma_34.h>
#include <dns/rdata/naptr_35.h>
#include <dns/rdata/kx_36.h>
#include <dns/rdata/cert_37.h>
#include <dns/rdata/a6_38.h>
#include <dns/rdata/dname_39.h>
#include <dns/rdata/sink_40.h>
#include <dns/rdata/opt_41.h>
#include <dns/rdata/apl_42.h>
#include <dns/rdata/ds_43.h>
#include <dns/rdata/sshfp_44.h>
#include <dns/rdata/ipseckey_45.h>
#include <dns/rdata/rrsig_46.h>
#include <dns/rdata/nsec_47.h>
#include <dns/rdata/dnskey_48.h>
#include <dns/rdata/dhcid_49.h>
#include <dns/rdata/nsec3_50.h>
#include <dns/rdata/nsec3param_51.h>
#include <dns/rdata/tlsa_52.h>
#include <dns/rdata/smimea_53.h>
#include <dns/rdata/hip_55.h>
#include <dns/rdata/ninfo_56.h>
#include <dns/rdata/rkey_57.h>
#include <dns/rdata/talink_58.h>
#include <dns/rdata/cds_59.h>
#include <dns/rdata/cdnskey_60.h>
#include <dns/rdata/openpgpkey_61.h>
#include <dns/rdata/csync_62.h>
#include <dns/rdata/zonemd_63.h>
#include <dns/rdata/svcb_64.h>
#include <dns/rdata/https_65.h>
#include <dns/rdata/dsync_66.h>
#include <dns/rdata/hhit_67.h>
#include <dns/rdata/brid_68.h>
#include <dns/rdata/spf_99.h>
#include <dns/rdata/nid_104.h>
#include <dns/rdata/l32_105.h>
#include <dns/rdata/l64_106.h>
#include <dns/rdata/lp_107.h>
#include <dns/rdata/eui48_108.h>
#include <dns/rdata/eui64_109.h>
#include <dns/rdata/tkey_249.h>
#include <dns/rdata/tsig_250.h>
#include <dns/rdata/uri_256.h>
#include <dns/rdata/caa_257.h>
#include <dns/rdata/avc_258.h>
#include <dns/rdata/doa_259.h>
#include <dns/rdata/amtrelay_260.h>
#include <dns/rdata/resinfo_261.h>
#include <dns/rdata/wallet_262.h>
#include <dns/rdata/ta_32768.h>
#include <dns/rdata/dlv_32769.h>
#include <dns/rdata/keydata_65533.h>
/* clang-format on */
