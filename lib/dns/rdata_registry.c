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

/*
 * First-character dispatch for type name lookup.
 * Each case checks only the types starting with that letter.
 */
#define NAMECMP(_s, _td)                                \
	if (sizeof(_s) - 1 == length &&                 \
	    strncasecmp(_s, name, sizeof(_s) - 1) == 0) \
	{                                               \
		return (_td);                           \
	}

const dns_rdata_typedesc_t *
dns__rdata_typedesc_fromtext(const char *name, unsigned int length) {
	if (length == 0) {
		return NULL;
	}

	switch (isc_ascii_tolower(name[0])) {
	case 'a':
		NAMECMP("A", typedesc_table[1]);
		NAMECMP("A6", typedesc_table[38]);
		NAMECMP("AAAA", typedesc_table[28]);
		NAMECMP("AFSDB", typedesc_table[18]);
		NAMECMP("AMTRELAY", typedesc_table[260]);
		NAMECMP("ANY", typedesc_table[255]);
		NAMECMP("APL", typedesc_table[42]);
		NAMECMP("ATMA", typedesc_table[34]);
		NAMECMP("AVC", typedesc_table[258]);
		NAMECMP("AXFR", typedesc_table[252]);
		break;
	case 'b':
		NAMECMP("BRID", typedesc_table[68]);
		break;
	case 'c':
		NAMECMP("CAA", typedesc_table[257]);
		NAMECMP("CDNSKEY", typedesc_table[60]);
		NAMECMP("CDS", typedesc_table[59]);
		NAMECMP("CERT", typedesc_table[37]);
		NAMECMP("CNAME", typedesc_table[5]);
		NAMECMP("CSYNC", typedesc_table[62]);
		break;
	case 'd':
		NAMECMP("DHCID", typedesc_table[49]);
		NAMECMP("DLV", typedesc_table[32769]);
		NAMECMP("DNAME", typedesc_table[39]);
		NAMECMP("DNSKEY", typedesc_table[48]);
		NAMECMP("DOA", typedesc_table[259]);
		NAMECMP("DS", typedesc_table[43]);
		NAMECMP("DSYNC", typedesc_table[66]);
		break;
	case 'e':
		NAMECMP("EID", typedesc_table[31]);
		NAMECMP("EUI48", typedesc_table[108]);
		NAMECMP("EUI64", typedesc_table[109]);
		break;
	case 'g':
		NAMECMP("GID", typedesc_table[102]);
		NAMECMP("GPOS", typedesc_table[27]);
		break;
	case 'h':
		NAMECMP("HHIT", typedesc_table[67]);
		NAMECMP("HINFO", typedesc_table[13]);
		NAMECMP("HIP", typedesc_table[55]);
		NAMECMP("HTTPS", typedesc_table[65]);
		break;
	case 'i':
		NAMECMP("IPSECKEY", typedesc_table[45]);
		NAMECMP("ISDN", typedesc_table[20]);
		NAMECMP("IXFR", typedesc_table[251]);
		break;
	case 'k':
		NAMECMP("KEY", typedesc_table[25]);
		NAMECMP("KEYDATA", typedesc_table[65533]);
		NAMECMP("KX", typedesc_table[36]);
		break;
	case 'l':
		NAMECMP("L32", typedesc_table[105]);
		NAMECMP("L64", typedesc_table[106]);
		NAMECMP("LOC", typedesc_table[29]);
		NAMECMP("LP", typedesc_table[107]);
		break;
	case 'm':
		NAMECMP("MAILA", typedesc_table[254]);
		NAMECMP("MAILB", typedesc_table[253]);
		NAMECMP("MB", typedesc_table[7]);
		NAMECMP("MD", typedesc_table[3]);
		NAMECMP("MF", typedesc_table[4]);
		NAMECMP("MG", typedesc_table[8]);
		NAMECMP("MINFO", typedesc_table[14]);
		NAMECMP("MR", typedesc_table[9]);
		NAMECMP("MX", typedesc_table[15]);
		break;
	case 'n':
		NAMECMP("NAPTR", typedesc_table[35]);
		NAMECMP("NID", typedesc_table[104]);
		NAMECMP("NIMLOC", typedesc_table[32]);
		NAMECMP("NINFO", typedesc_table[56]);
		NAMECMP("NS", typedesc_table[2]);
		NAMECMP("NSAP", typedesc_table[22]);
		NAMECMP("NSAP-PTR", typedesc_table[23]);
		NAMECMP("NSEC", typedesc_table[47]);
		NAMECMP("NSEC3", typedesc_table[50]);
		NAMECMP("NSEC3PARAM", typedesc_table[51]);
		NAMECMP("NULL", typedesc_table[10]);
		NAMECMP("NXT", typedesc_table[30]);
		break;
	case 'o':
		NAMECMP("OPENPGPKEY", typedesc_table[61]);
		NAMECMP("OPT", typedesc_table[41]);
		break;
	case 'p':
		NAMECMP("PTR", typedesc_table[12]);
		NAMECMP("PX", typedesc_table[26]);
		break;
	case 'r':
		NAMECMP("RESINFO", typedesc_table[261]);
		NAMECMP("RKEY", typedesc_table[57]);
		NAMECMP("RP", typedesc_table[17]);
		NAMECMP("RRSIG", typedesc_table[46]);
		NAMECMP("RT", typedesc_table[21]);
		break;
	case 's':
		NAMECMP("SIG", typedesc_table[24]);
		NAMECMP("SINK", typedesc_table[40]);
		NAMECMP("SMIMEA", typedesc_table[53]);
		NAMECMP("SOA", typedesc_table[6]);
		NAMECMP("SPF", typedesc_table[99]);
		NAMECMP("SRV", typedesc_table[33]);
		NAMECMP("SSHFP", typedesc_table[44]);
		NAMECMP("SVCB", typedesc_table[64]);
		break;
	case 't':
		NAMECMP("TA", typedesc_table[32768]);
		NAMECMP("TALINK", typedesc_table[58]);
		NAMECMP("TKEY", typedesc_table[249]);
		NAMECMP("TLSA", typedesc_table[52]);
		NAMECMP("TSIG", typedesc_table[250]);
		NAMECMP("TXT", typedesc_table[16]);
		break;
	case 'u':
		NAMECMP("UID", typedesc_table[101]);
		NAMECMP("UINFO", typedesc_table[100]);
		NAMECMP("UNSPEC", typedesc_table[103]);
		NAMECMP("URI", typedesc_table[256]);
		break;
	case 'w':
		NAMECMP("WALLET", typedesc_table[262]);
		NAMECMP("WKS", typedesc_table[11]);
		break;
	case 'x':
		NAMECMP("X25", typedesc_table[19]);
		break;
	case 'z':
		NAMECMP("ZONEMD", typedesc_table[63]);
		break;
	}

	return NULL;
}

#undef NAMECMP
