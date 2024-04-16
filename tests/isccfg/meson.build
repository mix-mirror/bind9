foreach unit : [
    'duration',
    'parser',
]
    test_bin = executable(
        unit,
        files(fs.replace_suffix(f'@unit@_test', '.c')),
        dependencies: [
            libisc_dep,
            libisccfg_dep,
            libtest_dep,

            cmocka_dep,
        ],
    )

    test(
        unit,
        test_bin,
        suite: 'isccfg',
        workdir: meson.current_source_dir(),
    )
endforeach
