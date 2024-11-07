#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <setjmp.h>
#include <unistd.h>

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

dns_rdata_t rdata_1 = DNS_RDATA_INIT;
dns_rdata_t rdata_2 = DNS_RDATA_INIT;
dns_rdata_t rdata_3 = DNS_RDATA_INIT;

ISC_RUN_TEST_IMPL(dns_diff_size) {
	dns_diff_t diff;
	dns_diff_init(mctx, &diff);

	assert_true(dns_diff_size(&diff) == 0);
	
	dns_difftuple_t *tup_1 = NULL, *tup_2 = NULL;
	dns_difftuple_create(mctx, DNS_DIFFOP_ADD, &name_1, 1, &rdata_1, &tup_1);
	dns_difftuple_create(mctx, DNS_DIFFOP_DEL, &name_2, 1, &rdata_2, &tup_2);

	dns_diff_append(&diff, &tup_1);
	assert_true(dns_diff_size(&diff) == 1);
	
	dns_diff_append(&diff, &tup_2);
	assert_true(dns_diff_size(&diff) == 2);

	dns_diff_clear(&diff);
	assert_true(dns_diff_size(&diff) == 0);
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY(dns_diff_size)
ISC_TEST_LIST_END

ISC_TEST_MAIN
