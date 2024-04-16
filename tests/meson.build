test_inc = include_directories(
    'include',
    '..' / 'lib' / 'isc',
    '..' / 'lib' / 'dns',
)

libtest = shared_library(
    'bindtest',
    files(
        'libtest/dns.c',
        'libtest/isc.c',
        'libtest/ns.c',
        'libtest/qp.c',
        'ns/netmgr_wrap.c',
    ),
    include_directories: test_inc,
    dependencies: [
        libdns_dep,
        libisc_dep,
        libisccfg_dep,
        libns_dep,
    ],
)

libtest_dep = declare_dependency(
    link_with: libtest,
    include_directories: test_inc,
)

if not cmocka_dep.found()
    subdir_done()
endif

subdir('bench')
subdir('dns')
subdir('irs')
subdir('isc')
subdir('isccfg')
subdir('ns')
