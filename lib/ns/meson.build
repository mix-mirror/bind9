ns_inc = include_directories('include')

subdir('include' / 'ns')

# Use sourceset to add conditional files
# https://mesonbuild.com/SourceSet-module.html
ns_srcset = ss.source_set()

ns_probe_target = static_library(
    'ns-probe-target',
    [
        dtrace_header.process('probes.d'),
        files('query.c'),
    ],
    build_by_default: false,
    dependencies: [libdns_dep, uv_dep, urcu_dep],
    include_directories: [isc_inc, ns_inc],
).extract_all_objects(recursive: false)

ns_srcset.add(
    custom_target(
        'ns-probe',
        input: ['probes.d', ns_probe_target],
        output: 'probes.o',
        command: [
            dtrace,
            '-G',
            '-o', '@OUTPUT@',
            '-s', '@INPUT@',
        ],
    ),
)

ns_srcset.add(
    files(
        'client.c',
        'hooks.c',
        'interfacemgr.c',
        'listenlist.c',
        'notify.c',
        'server.c',
        'sortlist.c',
        'stats.c',
        'update.c',
        'xfrout.c',
    ),
)

ns_srcconf = ns_srcset.apply(config, strict: false)

libns = shared_library(
    'ns',
    ns_srcconf.sources(),
    objects: ns_probe_target,
    install: true,
    include_directories: ns_inc,
    dependencies: [
        libisc_dep,
        libdns_dep,
    ],
)

libns_dep = declare_dependency(
    link_with: libns,
    include_directories: ns_inc,
    dependencies: [
        libisc_dep,
        libdns_dep,
    ],
)
