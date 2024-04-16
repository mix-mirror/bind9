foreach unit : [
    'resconf',
]
    test_bin = executable(
        unit,
        files(fs.replace_suffix(f'@unit@_test', '.c')),
        c_args: ['-DTESTS_DIR="@0@"'.format(meson.current_source_dir())],
        install: false,
        dependencies: [
            libisc_dep,
            libdns_dep,
            libtest_dep,

            cmocka_dep,
        ],
    )

    test(
        unit,
        test_bin,
        suite: 'irs',
        workdir: meson.current_source_dir(),
    )
endforeach
