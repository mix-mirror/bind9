#!/usr/bin/python
from cffi import FFI

ffibuilder = FFI()

# cdef() expects a single string declaring the C types, functions and
# globals needed to use the shared object. It must be in valid C syntax.
ffibuilder.cdef(
    """
typedef enum {ISC_R_SUCCESS, ISC_R_EXISTS, ISC_R_NOTFOUND, ISC_R_NOMORE, ISC_R_FAILURE, DNS_R_PARTIALMATCH, ...} isc_result_t;
typedef ... isc_mem_t;
typedef ... isc_buffer_t;

typedef struct { ...; } dns_name_t;
typedef struct { ...; } dns_fixedname_t;

typedef int... dns_qpshift_t;
typedef dns_qpshift_t dns_qpkey_t[...];
typedef ... dns_qp_t;
typedef ... dns_qpmulti_t;
typedef union { ...; } dns_qpreadable_t;
typedef struct { ...; } dns_qpmethods_t;

typedef struct { ...; } dns_qpiter_t;
typedef struct { ...; } dns_qpchain_t;

// FIXME: first argument's type is modified to make it work with CFFI
void
dns_qpiter_init(dns_qp_t *qpr, dns_qpiter_t *qpi);

isc_result_t
dns_qpiter_next(dns_qpiter_t *qpi, dns_name_t *name, void **pval_r,
		uint32_t *ival_r);
isc_result_t
dns_qpiter_prev(dns_qpiter_t *qpi, dns_name_t *name, void **pval_r,
		uint32_t *ival_r);

isc_result_t
dns_qpiter_current(dns_qpiter_t *qpi, dns_name_t *name, void **pval_r,
		   uint32_t *ival_r);

void
isc__mem_create(isc_mem_t **);

void
isc_mem_attach(isc_mem_t *, isc_mem_t **);

isc_result_t
dns_name_fromstring(dns_name_t *target, const char *src,
		    const dns_name_t *origin, unsigned int options,
		    isc_mem_t *mctx);

void
dns_name_format(const dns_name_t *name, char *cp, unsigned int size);

static inline void
dns_name_init(dns_name_t *name, unsigned char *offsets);

dns_name_t *
dns_fixedname_initname(dns_fixedname_t *fixed);

isc_result_t
dns_name_downcase(const dns_name_t *source, dns_name_t *name,
		  isc_buffer_t *target);

void
dns_qpkey_toname(const dns_qpkey_t key, size_t keylen, dns_name_t *name);

size_t
dns_qpkey_fromname(dns_qpkey_t key, const dns_name_t *name);

void
dns_qp_create(isc_mem_t *mctx, const dns_qpmethods_t *methods, void *uctx,
	      dns_qp_t **qptp);

void
dns_qpmulti_create(isc_mem_t *mctx, const dns_qpmethods_t *methods, void *uctx,
	      dns_qpmulti_t **qpmp);

extern const dns_qpmethods_t qp_methods;

isc_result_t
dns_qp_insert(dns_qp_t *qp, void *pval, uint32_t ival);

isc_result_t
dns_qp_deletename(dns_qp_t *qp, const dns_name_t *name, void **pval_r,
		  uint32_t *ival_r);

isc_result_t
dns_qp_getname(dns_qpreadable_t qpr, const dns_name_t *name, void **pval_r,
	       uint32_t *ival_r);

// FIXME: first argument's type is modified to make it work with CFFI
isc_result_t
dns_qp_lookup(dns_qp_t *qpr, const dns_name_t *name,
	      dns_name_t *foundname, dns_qpiter_t *iter, dns_qpchain_t *chain,
	      void **pval_r, uint32_t *ival_r);

// FIXME: first argument's type is modified to make it work with CFFI
void
dns_qpchain_init(dns_qp_t *qpr, dns_qpchain_t *chain);

unsigned int
dns_qpchain_length(dns_qpchain_t *chain);

void
dns_qpchain_node(dns_qpchain_t *chain, unsigned int level, dns_name_t *name,
		 void **pval_r, uint32_t *ival_r);
"""
)

# set_source() gives the name of the python extension module to
# produce, and some C source code as a string.  This C code needs
# to make the declarated functions, types and globals available,
# so it is often just the "#include".
ffibuilder.set_source(
    "_qp_test_cffi",
    """
    #include "isc/buffer.h"
    #include "isc/mem.h"
    #include "dns/name.h"
    #include "dns/fixedname.h"
    #include "dns/qp.h"

    static void
    noopref(void *uctx, void *pval, uint32_t ival) {}

    static void
    noopgetname(void *uctx, char *buf, size_t size) {}

    size_t
    qp_makekey(dns_qpkey_t key, void *uctx, void *pval,
           uint32_t ival) {
        dns_name_t *name = pval;
        return dns_qpkey_fromname(key, name);
    }

    const dns_qpmethods_t qp_methods = {
        noopref,
        noopref,
        qp_makekey,
        noopgetname,
    };
""",
    libraries=["dns"],
    include_dirs=["../../lib/isc/include", "../../lib/dns/include"],
)

if __name__ == "__main__":
    ffibuilder.compile(
        verbose=True,
    )
