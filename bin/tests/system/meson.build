configure_file(
    input: 'ifconfig.sh.in',
    output: 'ifconfig.sh',
    configuration: {
        'SYSTEM': target_machine.system(),
    },
)

executable(
    'feature-test',
    files('feature-test.c'),
    install: false,
    dependencies: [
        libdns_dep,
        libisc_dep,

        openssl_dep,
    ],
)

executable(
    'makejournal',
    files('makejournal.c'),
    install: false,
    dependencies: [
        libdns_dep,
        libisc_dep,
    ],
)

executable(
    'pipequeries',
    files('pipelined' / 'pipequeries.c'),
    install: false,
    dependencies: [
        libdns_dep,
        libisc_dep,
    ],
)

executable(
    'gencheck',
    files('rndc' / 'gencheck.c'),
    install: false,
    dependencies: [
        libdns_dep,
        libisc_dep,
    ],
)

if not pytest.found()
    subdir_done()
endif

system_test_env = {
    'TOP_BUILDDIR': meson.project_build_root(),
    'TOP_SRCDIR': meson.project_source_root(),
    'SHELL': sh.full_path(),
    'PERL': perl.full_path(),
}

foreach env, prog : {
    'CURL': curl,
    'XSLTPROC': xsltproc,
    'NC': nc,
    'FSTRM_CAPTURE': fstrm_capture,
    'PYTEST': pytest,
    'PYTHON': python,
}
    if prog.found()
        system_test_env += {env: prog.full_path()}
    endif
endforeach

foreach system : [
    'acl',
    'additional',
    'addzone',
    'allow-query',
    'auth',
    'autosign',
    'builtin',
    'cacheclean',
    'case',
    'catz',
    'cds',
    'chain',
    'checkconf',
    'checkds',
    'checknames',
    'checkzone',
    'cipher-suites',
    'cookie',
    'cpu',
    'database',
    'digdelv',
    'dispatch',
    'dlzexternal',
    'dns64',
    'dnssec',
    'dnstap',
    'doth',
    'dsdigest',
    'dyndb',
    'ecdsa',
    'eddsa',
    'ednscompliance',
    'emptyzones',
    'enginepkcs11',
    'fetchlimit',
    'filter-aaaa',
    'formerr',
    'forward',
    'geoip2',
    'glue',
    'hooks',
    'host',
    'idna',
    'include-multiplecfg',
    'inline',
    'integrity',
    'ixfr',
    'journal',
    'kasp',
    'keepalive',
    'keyfromlabel',
    'ksr',
    'legacy',
    'limits',
    'logfileconfig',
    'masterfile',
    'masterformat',
    'metadata',
    'mirror',
    'mkeys',
    'multisigner',
    'names',
    'notify',
    'nsec3',
    'nslookup',
    'nsupdate',
    'nzd2nzf',
    'padding',
    'pending',
    'pipelined',
    'proxy',
    'qmin',
    'query-source',
    'reclimit',
    'redirect',
    'resolver',
    'rndc',
    'rootkeysentinel',
    'rpz',
    'rpzextra',
    'rpzrecurse',
    'rrchcker',
    'rrl',
    'rrsetorder',
    'rsabigexponent',
    'runtime',
    'serve-stale',
    'sfcache',
    'shutdown',
    'smartsign',
    'sortlist',
    'spf',
    'staticstub',
    'statistics',
    'statschannel',
    'stress',
    'stub',
    'synthfromdnssec',
    'tcp',
    'timeouts',
    'tools',
    'transport-acl',
    'transport-change',
    'tsig',
    'tsiggss',
    'ttl',
    'unknown',
    'upforwd',
    'verify',
    'views',
    'wildcard',
    'xfer',
    'xferquota',
    'zero',
    'zonechecks',
]
    test(
        system,
        pytest,
        args: [system],
        suite: 'system',
        timeout: 360,
        env: system_test_env,
        workdir: meson.current_source_dir(),
    )
endforeach
