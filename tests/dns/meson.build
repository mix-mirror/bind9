master_data_script = fs.read('mkraw.pl', encoding: 'utf-8')

dns_tests = [
    'acl',
    'badcache',
    'db',
    'dbdiff',
    'dbiterator',
    'dbversion',
    'dispatch',
    'dns64',
    'dst',
    'keytable',
    'name',
    'nametree',
    'nsec3',
    'nsec3param',
    'private',
    'qp',
    'qpdb',
    'qpmulti',
    'qpzone',
    'rdata',
    'rdataset',
    'rdatasetstats',
    'resolver',
    'rsa',
    'time',
    'transport',
    'tsig',
    'update',
    'zonemgr',
    'zt',
]

if config.has('HAVE_GEOIP2')
    dns_tests += 'geoip'
endif

if config.has('HAVE_DNSTAP')
    dns_tests += 'dnstap'
endif

master_data = []
subdir('testdata/master')

foreach unit : dns_tests
    test_bin = executable(
        unit,
        files(fs.replace_suffix(f'@unit@_test', '.c')),
        build_by_default: false,
        c_args: [
            '-DSRCDIR="@0@"'.format(meson.current_source_dir()),
            '-DBUILDDIR="@0@"'.format(meson.current_build_dir()),
            '-DTESTS_DIR="@0@"'.format(meson.current_source_dir()),
            '-DTEST_GEOIP_DATA="@0@"'.format(
                meson.project_source_root() / 'bin' / 'tests' / 'system' / 'geoip2' / 'data',
            ),
        ],
        dependencies: [
            libisc_dep,
            libdns_dep,
            libns_dep,
            libtest_dep,

            openssl_dep,

            cmocka_dep,
            dnstap_dep,
            gssapi_dep,
            krb5_dep,
            maxminddb_dep,
            nghttp2_dep,
        ],
    )

    test(
        unit,
        test_bin,
        suite: 'dns',
        timeout: 180,
        workdir: meson.current_source_dir(),
    )
endforeach

foreach unit : ['master', 'sigs']
    test_bin = executable(
        unit,
        files(fs.replace_suffix(f'@unit@_test', '.c')),
        c_args: [
            '-DSRCDIR="@0@"'.format(meson.current_source_dir()),
            '-DBUILDDIR="@0@"'.format(meson.current_build_dir()),
            '-DTESTS_DIR="@0@"'.format(meson.current_source_dir()),
            '-DTEST_GEOIP_DATA="@0@"'.format(
                meson.project_source_root() / 'bin' / 'tests' / 'system' / 'geoip2' / 'data',
            ),
        ],
        dependencies: [
            libisc_dep,
            libdns_dep,
            libns_dep,
            libtest_dep,

            openssl_dep,

            cmocka_dep,
            dnstap_dep,
            gssapi_dep,
            krb5_dep,
            maxminddb_dep,
            nghttp2_dep,
        ],
    )

    test(
        unit,
        test_bin,
        suite: 'dns',
        depends: master_data,
        workdir: meson.current_build_dir(),
    )
endforeach
