executable(
    'nsupdate',
    files('nsupdate.c'),
    install: true,
    dependencies: [
        libdns_dep,
        libisc_dep,
        libisccfg_dep,

        gssapi_dep,
        krb5_dep,
        line_dep,
    ],
)
