foreach unit : [
    'notify',
    'plugin',
    'query',
]
    test_bin = executable(
        unit,
        files(fs.replace_suffix(f'@unit@_test', '.c'), 'netmgr_wrap.c'),
        build_by_default: false,
        dependencies: [
            libisc_dep,
            libdns_dep,
            libns_dep,
            libtest_dep,

            openssl_dep,

            cmocka_dep,
            nghttp2_dep,
        ],
    )

    test(
        unit,
        test_bin,
        suite: 'ns',
        workdir: meson.current_source_dir(),
    )
endforeach
