libisccc_inc = include_directories('include')

libisccc = shared_library(
    'isccc',
    files(
        'alist.c',
        'base64.c',
        'cc.c',
        'ccmsg.c',
        'sexpr.c',
        'symtab.c',
    ),
    include_directories: libisccc_inc,
    install: true,
    dependencies: [
        libdns_dep,
        libisc_dep,
    ],
)

libisccc_dep = declare_dependency(
    link_with: libisccc,
    include_directories: libisccc_inc,
)
