foreach bench : [
    'ascii',
    'compress',
    'iterated_hash',
    'load-names',
    'qp-dump',
    'qplookups',
    'qpmulti',
    'siphash',
]
    executable(
        bench,
        files(fs.replace_suffix(bench, '.c')),
        install: false,
        dependencies: [
            libisc_dep,
            libdns_dep,
            libns_dep,
            libtest_dep,
        ],
    )
endforeach

executable(
    'dns_name_fromwire',
    files(
        'dns_name_fromwire.c',
        meson.project_source_root() / 'fuzz' / 'old.c',
    ),
    install: false,
    include_directories: '..' / '..' / 'fuzz',
    dependencies: [
        libisc_dep,
        libdns_dep,
        libns_dep,
        libtest_dep,
    ],

)
