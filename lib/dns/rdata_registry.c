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
 * Rdata type registry.
 *
 * Direct-indexed lookup table: typedesc_table[type_code] gives the
 * type descriptor for any type code 0..65535.  NULL entries mean
 * the type is unknown.  512KB for the table (65536 * 8-byte pointers).
 */

#include <stddef.h>
#include <string.h>

#include <isc/ascii.h>
#include <isc/util.h>

#include <dns/rdata.h>
#include <dns/rdataclass.h>
#include <dns/rdatatype.h>

#include "rdata_p.h"

/*
 * Extern declarations for type descriptors.
 */
extern const dns_rdata_typedesc_t dns__rdata_in_a_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_ns_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_md_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_mf_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_cname_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_soa_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_mb_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_mg_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_mr_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_null_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_in_wks_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_ptr_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_hinfo_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_minfo_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_mx_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_txt_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_rp_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_afsdb_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_x25_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_isdn_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_rt_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_in_nsap_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_in_nsap_ptr_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_sig_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_key_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_in_px_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_gpos_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_in_aaaa_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_loc_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_nxt_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_in_eid_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_in_nimloc_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_in_srv_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_in_atma_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_naptr_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_in_kx_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_cert_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_in_a6_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_dname_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_sink_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_opt_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_in_apl_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_ds_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_sshfp_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_ipseckey_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_rrsig_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_nsec_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_dnskey_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_in_dhcid_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_nsec3_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_nsec3param_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_tlsa_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_smimea_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_hip_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_ninfo_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_rkey_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_talink_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_cds_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_cdnskey_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_openpgpkey_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_csync_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_zonemd_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_in_svcb_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_in_https_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_dsync_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_hhit_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_brid_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_spf_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_nid_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_l32_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_l64_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_lp_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_eui48_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_eui64_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_tkey_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_any_tsig_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_uri_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_caa_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_avc_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_doa_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_amtrelay_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_resinfo_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_wallet_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_ta_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_dlv_typedesc;
extern const dns_rdata_typedesc_t dns__rdata_keydata_typedesc;

/*
 * Meta-types and reserved types.  These have no rdata methods — they
 * exist only so that dns_rdatatype_fromtext(), dns_rdatatype_totext(),
 * and dns_rdatatype_attributes() recognize them.
 */
#define METAQUESTIONONLY \
	(DNS_RDATATYPEATTR_META | DNS_RDATATYPEATTR_QUESTIONONLY)

static const dns_rdata_typedesc_t typedesc_uinfo = { 100, 0, "UINFO", 0, NULL };
static const dns_rdata_typedesc_t typedesc_uid = { 101, 0, "UID", 0, NULL };
static const dns_rdata_typedesc_t typedesc_gid = { 102, 0, "GID", 0, NULL };
static const dns_rdata_typedesc_t typedesc_unspec = { 103, 0, "UNSPEC", 0,
						      NULL };
static const dns_rdata_typedesc_t typedesc_ixfr = { 251, 0, "IXFR",
						    METAQUESTIONONLY, NULL };
static const dns_rdata_typedesc_t typedesc_axfr = { 252, 0, "AXFR",
						    METAQUESTIONONLY, NULL };
static const dns_rdata_typedesc_t typedesc_mailb = { 253, 0, "MAILB",
						     METAQUESTIONONLY, NULL };
static const dns_rdata_typedesc_t typedesc_maila = { 254, 0, "MAILA",
						     METAQUESTIONONLY, NULL };
static const dns_rdata_typedesc_t typedesc_any = { 255, 0, "ANY",
						   METAQUESTIONONLY, NULL };

/*
 * Direct-indexed lookup table.  typedesc_table[N] is the descriptor
 * for type code N, or NULL if the type is unknown.
 *
 * Uses C designated initializers: unmentioned entries are NULL.
 */
static const dns_rdata_typedesc_t *const typedesc_table[65536] = {
	[1] = &dns__rdata_in_a_typedesc,
	[2] = &dns__rdata_ns_typedesc,
	[3] = &dns__rdata_md_typedesc,
	[4] = &dns__rdata_mf_typedesc,
	[5] = &dns__rdata_cname_typedesc,
	[6] = &dns__rdata_soa_typedesc,
	[7] = &dns__rdata_mb_typedesc,
	[8] = &dns__rdata_mg_typedesc,
	[9] = &dns__rdata_mr_typedesc,
	[10] = &dns__rdata_null_typedesc,
	[11] = &dns__rdata_in_wks_typedesc,
	[12] = &dns__rdata_ptr_typedesc,
	[13] = &dns__rdata_hinfo_typedesc,
	[14] = &dns__rdata_minfo_typedesc,
	[15] = &dns__rdata_mx_typedesc,
	[16] = &dns__rdata_txt_typedesc,
	[17] = &dns__rdata_rp_typedesc,
	[18] = &dns__rdata_afsdb_typedesc,
	[19] = &dns__rdata_x25_typedesc,
	[20] = &dns__rdata_isdn_typedesc,
	[21] = &dns__rdata_rt_typedesc,
	[22] = &dns__rdata_in_nsap_typedesc,
	[23] = &dns__rdata_in_nsap_ptr_typedesc,
	[24] = &dns__rdata_sig_typedesc,
	[25] = &dns__rdata_key_typedesc,
	[26] = &dns__rdata_in_px_typedesc,
	[27] = &dns__rdata_gpos_typedesc,
	[28] = &dns__rdata_in_aaaa_typedesc,
	[29] = &dns__rdata_loc_typedesc,
	[30] = &dns__rdata_nxt_typedesc,
	[31] = &dns__rdata_in_eid_typedesc,
	[32] = &dns__rdata_in_nimloc_typedesc,
	[33] = &dns__rdata_in_srv_typedesc,
	[34] = &dns__rdata_in_atma_typedesc,
	[35] = &dns__rdata_naptr_typedesc,
	[36] = &dns__rdata_in_kx_typedesc,
	[37] = &dns__rdata_cert_typedesc,
	[38] = &dns__rdata_in_a6_typedesc,
	[39] = &dns__rdata_dname_typedesc,
	[40] = &dns__rdata_sink_typedesc,
	[41] = &dns__rdata_opt_typedesc,
	[42] = &dns__rdata_in_apl_typedesc,
	[43] = &dns__rdata_ds_typedesc,
	[44] = &dns__rdata_sshfp_typedesc,
	[45] = &dns__rdata_ipseckey_typedesc,
	[46] = &dns__rdata_rrsig_typedesc,
	[47] = &dns__rdata_nsec_typedesc,
	[48] = &dns__rdata_dnskey_typedesc,
	[49] = &dns__rdata_in_dhcid_typedesc,
	[50] = &dns__rdata_nsec3_typedesc,
	[51] = &dns__rdata_nsec3param_typedesc,
	[52] = &dns__rdata_tlsa_typedesc,
	[53] = &dns__rdata_smimea_typedesc,
	[55] = &dns__rdata_hip_typedesc,
	[56] = &dns__rdata_ninfo_typedesc,
	[57] = &dns__rdata_rkey_typedesc,
	[58] = &dns__rdata_talink_typedesc,
	[59] = &dns__rdata_cds_typedesc,
	[60] = &dns__rdata_cdnskey_typedesc,
	[61] = &dns__rdata_openpgpkey_typedesc,
	[62] = &dns__rdata_csync_typedesc,
	[63] = &dns__rdata_zonemd_typedesc,
	[64] = &dns__rdata_in_svcb_typedesc,
	[65] = &dns__rdata_in_https_typedesc,
	[66] = &dns__rdata_dsync_typedesc,
	[67] = &dns__rdata_hhit_typedesc,
	[68] = &dns__rdata_brid_typedesc,
	[99] = &dns__rdata_spf_typedesc,
	[100] = &typedesc_uinfo,
	[101] = &typedesc_uid,
	[102] = &typedesc_gid,
	[103] = &typedesc_unspec,
	[104] = &dns__rdata_nid_typedesc,
	[105] = &dns__rdata_l32_typedesc,
	[106] = &dns__rdata_l64_typedesc,
	[107] = &dns__rdata_lp_typedesc,
	[108] = &dns__rdata_eui48_typedesc,
	[109] = &dns__rdata_eui64_typedesc,
	[249] = &dns__rdata_tkey_typedesc,
	[250] = &dns__rdata_any_tsig_typedesc,
	[251] = &typedesc_ixfr,
	[252] = &typedesc_axfr,
	[253] = &typedesc_mailb,
	[254] = &typedesc_maila,
	[255] = &typedesc_any,
	[256] = &dns__rdata_uri_typedesc,
	[257] = &dns__rdata_caa_typedesc,
	[258] = &dns__rdata_avc_typedesc,
	[259] = &dns__rdata_doa_typedesc,
	[260] = &dns__rdata_amtrelay_typedesc,
	[261] = &dns__rdata_resinfo_typedesc,
	[262] = &dns__rdata_wallet_typedesc,
	[32768] = &dns__rdata_ta_typedesc,
	[32769] = &dns__rdata_dlv_typedesc,
	[65533] = &dns__rdata_keydata_typedesc,
};

const dns_rdata_typedesc_t *
dns__rdata_typedesc_lookup(dns_rdataclass_t rdclass, dns_rdatatype_t type) {
	const dns_rdata_typedesc_t *td = typedesc_table[type];

	/*
	 * Class-specific types (rdclass != 0) are only valid for their
	 * own class.  Return NULL for mismatches so the caller falls
	 * through to default (unknown-type) handling.
	 */
	if (td != NULL && td->rdclass != 0 && td->rdclass != rdclass) {
		return NULL;
	}

	return td;
}

const dns_rdata_typedesc_t *
dns__rdata_typedesc_bytype(dns_rdatatype_t type) {
	return typedesc_table[type];
}

const dns_rdata_typedesc_t *
dns__rdata_typedesc_fromtext(const char *name, unsigned int length) {
	/*
	 * Linear scan — only called during zone loading / config parsing,
	 * not on the hot path.  With ~85 entries this is fast enough.
	 */
	for (unsigned int i = 0; i < 65536; i++) {
		const dns_rdata_typedesc_t *td = typedesc_table[i];

		if (td == NULL || td->name == NULL) {
			continue;
		}

		if (strlen(td->name) == length &&
		    strncasecmp(td->name, name, length) == 0)
		{
			return td;
		}
	}

	return NULL;
}
