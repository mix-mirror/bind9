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
 * Maps (rdclass, type) pairs to type descriptors containing method
 * tables and metadata.  The table is sorted by (type, rdclass) for
 * binary search.  Generic (class-independent) entries have rdclass=0
 * and serve as fallback when no class-specific entry exists.
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
 * Extern declarations for type descriptors defined in rdata type files.
 * Currently compiled as part of rdata.c (via #include of code.h).
 * Sorted by (type, rdclass) to match the table order.
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
 * Type descriptor table, sorted by (type, rdclass).
 * All known rdata types are registered here.
 */
static const dns_rdata_typedesc_t *const typedesc_table[] = {
	&dns__rdata_in_a_typedesc,	  /* 1/IN */
	&dns__rdata_ns_typedesc,	  /* 2 */
	&dns__rdata_md_typedesc,	  /* 3 */
	&dns__rdata_mf_typedesc,	  /* 4 */
	&dns__rdata_cname_typedesc,	  /* 5 */
	&dns__rdata_soa_typedesc,	  /* 6 */
	&dns__rdata_mb_typedesc,	  /* 7 */
	&dns__rdata_mg_typedesc,	  /* 8 */
	&dns__rdata_mr_typedesc,	  /* 9 */
	&dns__rdata_null_typedesc,	  /* 10 */
	&dns__rdata_in_wks_typedesc,	  /* 11/IN */
	&dns__rdata_ptr_typedesc,	  /* 12 */
	&dns__rdata_hinfo_typedesc,	  /* 13 */
	&dns__rdata_minfo_typedesc,	  /* 14 */
	&dns__rdata_mx_typedesc,	  /* 15 */
	&dns__rdata_txt_typedesc,	  /* 16 */
	&dns__rdata_rp_typedesc,	  /* 17 */
	&dns__rdata_afsdb_typedesc,	  /* 18 */
	&dns__rdata_x25_typedesc,	  /* 19 */
	&dns__rdata_isdn_typedesc,	  /* 20 */
	&dns__rdata_rt_typedesc,	  /* 21 */
	&dns__rdata_in_nsap_typedesc,	  /* 22/IN */
	&dns__rdata_in_nsap_ptr_typedesc, /* 23/IN */
	&dns__rdata_sig_typedesc,	  /* 24 */
	&dns__rdata_key_typedesc,	  /* 25 */
	&dns__rdata_in_px_typedesc,	  /* 26/IN */
	&dns__rdata_gpos_typedesc,	  /* 27 */
	&dns__rdata_in_aaaa_typedesc,	  /* 28/IN */
	&dns__rdata_loc_typedesc,	  /* 29 */
	&dns__rdata_nxt_typedesc,	  /* 30 */
	&dns__rdata_in_eid_typedesc,	  /* 31/IN */
	&dns__rdata_in_nimloc_typedesc,	  /* 32/IN */
	&dns__rdata_in_srv_typedesc,	  /* 33/IN */
	&dns__rdata_in_atma_typedesc,	  /* 34/IN */
	&dns__rdata_naptr_typedesc,	  /* 35 */
	&dns__rdata_in_kx_typedesc,	  /* 36/IN */
	&dns__rdata_cert_typedesc,	  /* 37 */
	&dns__rdata_in_a6_typedesc,	  /* 38/IN */
	&dns__rdata_dname_typedesc,	  /* 39 */
	&dns__rdata_sink_typedesc,	  /* 40 */
	&dns__rdata_opt_typedesc,	  /* 41 */
	&dns__rdata_in_apl_typedesc,	  /* 42/IN */
	&dns__rdata_ds_typedesc,	  /* 43 */
	&dns__rdata_sshfp_typedesc,	  /* 44 */
	&dns__rdata_ipseckey_typedesc,	  /* 45 */
	&dns__rdata_rrsig_typedesc,	  /* 46 */
	&dns__rdata_nsec_typedesc,	  /* 47 */
	&dns__rdata_dnskey_typedesc,	  /* 48 */
	&dns__rdata_in_dhcid_typedesc,	  /* 49/IN */
	&dns__rdata_nsec3_typedesc,	  /* 50 */
	&dns__rdata_nsec3param_typedesc,  /* 51 */
	&dns__rdata_tlsa_typedesc,	  /* 52 */
	&dns__rdata_smimea_typedesc,	  /* 53 */
	&dns__rdata_hip_typedesc,	  /* 55 */
	&dns__rdata_ninfo_typedesc,	  /* 56 */
	&dns__rdata_rkey_typedesc,	  /* 57 */
	&dns__rdata_talink_typedesc,	  /* 58 */
	&dns__rdata_cds_typedesc,	  /* 59 */
	&dns__rdata_cdnskey_typedesc,	  /* 60 */
	&dns__rdata_openpgpkey_typedesc,  /* 61 */
	&dns__rdata_csync_typedesc,	  /* 62 */
	&dns__rdata_zonemd_typedesc,	  /* 63 */
	&dns__rdata_in_svcb_typedesc,	  /* 64/IN */
	&dns__rdata_in_https_typedesc,	  /* 65/IN */
	&dns__rdata_dsync_typedesc,	  /* 66 */
	&dns__rdata_hhit_typedesc,	  /* 67 */
	&dns__rdata_brid_typedesc,	  /* 68 */
	&dns__rdata_spf_typedesc,	  /* 99 */
	&typedesc_uinfo,		  /* 100 (reserved) */
	&typedesc_uid,			  /* 101 (reserved) */
	&typedesc_gid,			  /* 102 (reserved) */
	&typedesc_unspec,		  /* 103 (reserved) */
	&dns__rdata_nid_typedesc,	  /* 104 */
	&dns__rdata_l32_typedesc,	  /* 105 */
	&dns__rdata_l64_typedesc,	  /* 106 */
	&dns__rdata_lp_typedesc,	  /* 107 */
	&dns__rdata_eui48_typedesc,	  /* 108 */
	&dns__rdata_eui64_typedesc,	  /* 109 */
	&dns__rdata_tkey_typedesc,	  /* 249 */
	&dns__rdata_any_tsig_typedesc,	  /* 250/ANY */
	&typedesc_ixfr,			  /* 251 (meta) */
	&typedesc_axfr,			  /* 252 (meta) */
	&typedesc_mailb,		  /* 253 (meta) */
	&typedesc_maila,		  /* 254 (meta) */
	&typedesc_any,			  /* 255 (meta) */
	&dns__rdata_uri_typedesc,	  /* 256 */
	&dns__rdata_caa_typedesc,	  /* 257 */
	&dns__rdata_avc_typedesc,	  /* 258 */
	&dns__rdata_doa_typedesc,	  /* 259 */
	&dns__rdata_amtrelay_typedesc,	  /* 260 */
	&dns__rdata_resinfo_typedesc,	  /* 261 */
	&dns__rdata_wallet_typedesc,	  /* 262 */
	&dns__rdata_ta_typedesc,	  /* 32768 */
	&dns__rdata_dlv_typedesc,	  /* 32769 */
	&dns__rdata_keydata_typedesc,	  /* 65533 */
};

static const size_t typedesc_count = sizeof(typedesc_table) /
				     sizeof(typedesc_table[0]);

/*
 * Binary search for (type, rdclass) in the sorted table.
 * Returns the matching entry or NULL.
 */
static const dns_rdata_typedesc_t *
typedesc_find(dns_rdataclass_t rdclass, dns_rdatatype_t type) {
	size_t lo = 0;
	size_t hi = typedesc_count;

	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;
		const dns_rdata_typedesc_t *td = typedesc_table[mid];

		if (td->type < type ||
		    (td->type == type && td->rdclass < rdclass))
		{
			lo = mid + 1;
		} else if (td->type == type && td->rdclass == rdclass) {
			return td;
		} else {
			hi = mid;
		}
	}

	return NULL;
}

/*
 * Find any entry for a given type code, regardless of class.
 * Used for type name/attribute lookups where class doesn't matter.
 */
static const dns_rdata_typedesc_t *
typedesc_find_bytype(dns_rdatatype_t type) {
	size_t lo = 0;
	size_t hi = typedesc_count;

	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;
		const dns_rdata_typedesc_t *td = typedesc_table[mid];

		if (td->type < type) {
			lo = mid + 1;
		} else if (td->type == type) {
			return td;
		} else {
			hi = mid;
		}
	}

	return NULL;
}

const dns_rdata_typedesc_t *
dns__rdata_typedesc_lookup(dns_rdataclass_t rdclass, dns_rdatatype_t type) {
	const dns_rdata_typedesc_t *td;

	/* Try exact (rdclass, type) match first */
	td = typedesc_find(rdclass, type);
	if (td != NULL) {
		return td;
	}

	/* Fall back to generic (rdclass=0) entry */
	if (rdclass != 0) {
		td = typedesc_find(0, type);
	}

	return td;
}

const dns_rdata_typedesc_t *
dns__rdata_typedesc_bytype(dns_rdatatype_t type) {
	return typedesc_find_bytype(type);
}

const dns_rdata_typedesc_t *
dns__rdata_typedesc_fromtext(const char *name, unsigned int length) {
	for (size_t i = 0; i < typedesc_count; i++) {
		const dns_rdata_typedesc_t *td = typedesc_table[i];

		if (td->name == NULL) {
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
