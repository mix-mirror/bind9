executable(
    'arpaname',
    files('arpaname.c'),
    install: true,
    dependencies: [
        libisc_dep,
    ],
)

executable(
    'mdig',
    files('mdig.c'),
    install: true,
    dependencies: [
        libdns_dep,
        libisc_dep,
    ],
)

executable(
    'named-journalprint',
    files('named-journalprint.c'),
    install: true,
    dependencies: [
        libdns_dep,
        libisc_dep,
    ],
)

executable(
    'named-rrchecker',
    files('named-rrchecker.c'),
    install: true,
    dependencies: [
        libdns_dep,
        libisc_dep,
    ],
)

executable(
    'nsec3hash',
    files('nsec3hash.c'),
    install: true,
    dependencies: [
        libdns_dep,
        libisc_dep,
    ],
)

if config.has('HAVE_LMDB')
    executable(
        'named-nzd2nzf',
        files('named-nzd2nzf.c'),
        install: true,
        dependencies: [
            libdns_dep,
            libisc_dep,

            lmdb_dep,
        ],
    )
endif

if config.has('HAVE_DNSTAP')
    executable(
        'dnstap-read',
        files('dnstap-read.c'),
        install: true,
        dependencies: [
            libdns_dep,
            libisc_dep,

            dnstap_dep,
        ],
    )
endif
