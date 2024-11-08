#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <setjmp.h>
#include <unistd.h>
#include "isc/list.h"

#define UNIT_TESTING
#include <cmocka.h>

#include <dns/diff.h>

#include <tests/dns.h>

unsigned char data_1[] = "\006name_1";
unsigned char offsets_1[] = { 0, 7 };
dns_name_t name_1 = DNS_NAME_INITABSOLUTE(data_1, offsets_1);

unsigned char data_2[] = "\006name_2";
unsigned char offsets_2[] = { 0, 7 };
dns_name_t name_2 = DNS_NAME_INITABSOLUTE(data_2, offsets_2);

unsigned char data_3[] = "\006name_3";
unsigned char offsets_3[] = { 0, 7 };
dns_name_t name_3 = DNS_NAME_INITABSOLUTE(data_3, offsets_3);

unsigned char data_dup[] = "\006name_1";
unsigned char offsets_dup[] = {0, 7};
dns_name_t name_dup = DNS_NAME_INITABSOLUTE(data_dup, offsets_dup);

unsigned char data_nodup[] = "\006name_1";
unsigned char offsets_nodup[] = {0, 7};
dns_name_t name_nodup = DNS_NAME_INITABSOLUTE(data_nodup, offsets_nodup);

dns_rdata_t rdata_1 = DNS_RDATA_INIT;
dns_rdata_t rdata_2 = DNS_RDATA_INIT;
dns_rdata_t rdata_3 = DNS_RDATA_INIT;
dns_rdata_t rdata_dup = DNS_RDATA_INIT;
dns_rdata_t rdata_nodup = DNS_RDATA_INIT;

static size_t count_elements(const dns_diff_t *diff) {
	dns_difftuple_t *ot = NULL;
	size_t count = 0;

	for (ot = ISC_LIST_HEAD(diff->tuples); ot != NULL; ot = ISC_LIST_NEXT(ot, link)) {
		++count;
	}

	return count;
}

ISC_RUN_TEST_IMPL(dns_diff_size) {
	dns_diff_t diff;
	dns_diff_init(mctx, &diff);

	assert_true(dns_diff_size(&diff) == 0);
	
	dns_difftuple_t *tup_1 = NULL, *tup_2 = NULL, *tup_3 = NULL;
	dns_difftuple_create(mctx, DNS_DIFFOP_ADD, &name_1, 1, &rdata_1, &tup_1);
	dns_difftuple_create(mctx, DNS_DIFFOP_DEL, &name_2, 1, &rdata_2, &tup_2);
	dns_difftuple_create(mctx, DNS_DIFFOP_DEL, &name_3, 1, &rdata_3, &tup_3);

	dns_difftuple_t *tup_dup = NULL, *tup_nodup = NULL;
	dns_difftuple_create(mctx, DNS_DIFFOP_DEL, &name_dup, 1, &rdata_dup, &tup_dup);
	dns_difftuple_create(mctx, DNS_DIFFOP_ADD, &name_nodup, 1, &rdata_nodup, &tup_nodup);
	(void)tup_dup;
	(void)tup_nodup;

	dns_diff_append(&diff, &tup_1);
	assert_true(dns_diff_size(&diff) == 1);
	assert_true(dns_diff_size(&diff) == count_elements(&diff));
	
	dns_diff_append(&diff, &tup_2);
	assert_true(dns_diff_size(&diff) == 2);
	assert_true(dns_diff_size(&diff) == count_elements(&diff));

	dns_diff_appendminimal(&diff, &tup_dup);
	assert_true(dns_diff_size(&diff) == 1);
	assert_true(dns_diff_size(&diff) == count_elements(&diff));

	dns_diff_append(&diff, &tup_3);
	assert_true(dns_diff_size(&diff) == 2);
	assert_true(dns_diff_size(&diff) == count_elements(&diff));
	
	dns_diff_appendminimal(&diff, &tup_nodup);
	assert_true(dns_diff_size(&diff) == 3);
	assert_true(dns_diff_size(&diff) == count_elements(&diff));
	
	dns_diff_clear(&diff);
	assert_true(dns_diff_size(&diff) == 0);
	assert_true(dns_diff_size(&diff) == count_elements(&diff));

	dns_difftuple_t* to_clear[] = {tup_1, tup_2, tup_3, tup_dup, tup_nodup};
	size_t to_clear_size = sizeof(to_clear) / sizeof(*to_clear);

	for (size_t idx = 0; idx < to_clear_size; ++idx) {
		if (to_clear[idx] != NULL) {
			printf("Tuple %zu is not null\n", idx);
			dns_difftuple_free(&to_clear[idx]);
		}
	}
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY(dns_diff_size)
ISC_TEST_LIST_END

ISC_TEST_MAIN
