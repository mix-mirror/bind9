# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0
#
# Meson glue to build the pinned userspace-rcu as a subproject. At the
# wrapped commit userspace-rcu ships only an autotools build, so rather
# than reimplement it we drive its own configure/make through meson's
# external_project module. Everything liburcu-specific -- feature
# detection, the flavor libraries, and the fractal-trie lookup-cluster
# linker script (ft-lookup-layout.ld) -- is left to liburcu's configure.

project(
    'userspace-rcu',
    'c',
    version: '0.15.0',
    license: 'LGPL-2.1-or-later',
    meson_version: '>=1.3.0',
)

fs = import('fs')
emod = import('unstable-external_project')

# The git checkout provides configure.ac but no generated configure
# script; run ./bootstrap (autoreconf) once, in the source tree, to
# create it. Guarded so it only runs on a fresh checkout.
if not fs.exists(meson.current_source_dir() / 'configure')
    run_command(
        'sh',
        '-c',
        'cd @0@ && exec ./bootstrap'.format(meson.current_source_dir()),
        check: true,
    )
endif

urcu = emod.add_project(
    'configure',
    configure_options: [
        '--prefix=@PREFIX@',
        '--libdir=@PREFIX@/@LIBDIR@',
        '--includedir=@PREFIX@/@INCLUDEDIR@',
        '--disable-static',
    ],
)

# Wrap each flavour in declare_dependency() so the dependency carries a
# version (external_project dependencies report none), which the parent
# project's `dependency(..., version: ...)` checks and RCU_VERSION rely
# on. The library names are liburcu's installed sonames without the
# 'lib' prefix; 'urcu' is the default (membarrier) flavour.
_ver = meson.project_version()
urcu_cds_dep = declare_dependency(
    version: _ver,
    dependencies: urcu.dependency('urcu-cds'),
)
urcu_memb_dep = declare_dependency(
    version: _ver,
    dependencies: urcu.dependency('urcu'),
)
urcu_mb_dep = declare_dependency(
    version: _ver,
    dependencies: urcu.dependency('urcu-mb'),
)
urcu_bp_dep = declare_dependency(
    version: _ver,
    dependencies: urcu.dependency('urcu-bp'),
)
urcu_qsbr_dep = declare_dependency(
    version: _ver,
    dependencies: urcu.dependency('urcu-qsbr'),
)
