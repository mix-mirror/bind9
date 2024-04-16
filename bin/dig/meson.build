executable(
    'dig',
    files('dig.c', 'dighost.c'),
    install: true,
    dependencies: [
        libdns_dep,
        libisc_dep,
        libisccfg_dep,

        idn2_dep,
    ],
)

executable(
    'nslookup',
    files('dighost.c', 'nslookup.c'),
    install: true,
    dependencies: [
        libdns_dep,
        libisc_dep,
        libisccfg_dep,

        idn2_dep,
        line_dep,
    ],
)
