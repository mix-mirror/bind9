# Use sourceset to add conditional files
# https://mesonbuild.com/SourceSet-module.html
named_srcset = ss.source_set()

named_srcset.add(when: 'HAVE_GEOIP2', if_true: [files('geoip.c'), maxminddb_dep])

named_srcset.add(bind_keys)

named_srcset.add(
    configure_file(
        input: 'xsl_c.in',
        output: 'xsl.c',
        configuration: {
            'XSL': '\\n'.join(fs.read('bind9.xsl').strip().replace('"', '\\"').split('\n')),
        },
    ),
)

named_srcset.add(
    files(
        'builtin.c',
        'config.c',
        'control.c',
        'controlconf.c',
        'dlz_dlopen_driver.c',
        'fuzz.c',
        'log.c',
        'logconf.c',
        'main.c',
        'os.c',
        'server.c',
        'statschannel.c',
        'tkeyconf.c',
        'transportconf.c',
        'tsigconf.c',
        'zoneconf.c',
    ),
)

named_srcconf = named_srcset.apply(config, strict: false)

executable(
    'named',
    named_srcconf.sources(),
    install: true,
    include_directories: 'include',
    dependencies: [
        libdns_dep,
        libisc_dep,
        libisccc_dep,
        libisccfg_dep,
        libns_dep,

        openssl_dep,

        dnstap_dep,
        json_c_dep,
        lmdb_dep,
        nghttp2_dep,
        systemd_dep,
        xml2_dep,
        zlib_dep,

        named_srcconf.dependencies(),
    ],
)
