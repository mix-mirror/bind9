libisccfg_inc = include_directories('include')

subdir('include' / 'isccfg')

libisccfg = shared_library(
    'isccfg',
    files(
        'aclconf.c',
        'check.c',
        'duration.c',
        'kaspconf.c',
        'namedconf.c',
        'parser.c',
    ),
    include_directories: libisccfg_inc,
    install: true,
    dependencies: [
        libdns_dep,
        libisc_dep,
        libns_dep,

        dnstap_dep,
    ],
)

libisccfg_dep = declare_dependency(
    link_with: libisccfg,
    include_directories: libisccfg_inc,
)
