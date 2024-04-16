isc_test = [
    'ascii',
    'async',
    'buffer',
    'counter',
    'dnsstream_utils',
    'errno',
    'file',
    'hash',
    'hashmap',
    'heap',
    'histo',
    'hmac',
    'ht',
    'job',
    'lex',
    'loop',
    'md',
    'mem',
    'mutex',
    'netaddr',
    'parse',
    'proxyheader',
    'proxystream',
    'proxyudp',
    'quota',
    'radix',
    'random',
    'ratelimiter',
    'regex',
    'result',
    'rwlock',
    'safe',
    'siphash',
    'sockaddr',
    'spinlock',
    'stats',
    'symtab',
    'tcp',
    'tcpdns',
    'time',
    'timer',
    'tls',
    'tlsdns',
    'udp',
    'work',
]

if config.has('HAVE_NGHTTP2')
    isc_test += 'doh'
endif

foreach unit : isc_test
    test_bin = executable(
        unit,
        files(
            fs.replace_suffix(f'@unit@_test', '.c'),
            'netmgr_common.c',
            'stream_shutdown.c',
        ),
        build_by_default: false,
        dependencies: [
            libisc_dep,
            libtest_dep,

            m_dep,
            openssl_dep,

            cmocka_dep,
            nghttp2_dep,
        ],
    )

    test(
        unit,
        test_bin,
        suite: 'isc',
        workdir: meson.current_source_dir(),
    )
endforeach
