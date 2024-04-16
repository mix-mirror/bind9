confgen_inc = include_directories('include')
confgen_src = files('keygen.c', 'os.c', 'util.c')

executable(
    'tsig-keygen',
    [files('tsig-keygen.c'), confgen_src],
    install: true,
    include_directories: confgen_inc,
    dependencies: [
        libdns_dep,
        libisc_dep,
    ],
)

executable(
    'rndc-confgen',
    [files('rndc-confgen.c'), confgen_src],
    install: true,
    include_directories: confgen_inc,
    dependencies: [
        libdns_dep,
        libisc_dep,
    ],
)
