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
#
# liburcu-common holds the wait-free queue/stack primitives (cds_wfcq_*,
# cds_wfs_*, ...) that both the flavours and callers link against. A
# system liburcu chains it in via liburcu-cds.pc's Libs line, but the
# external_project dependencies are flat (just -l<name>), so fold it into
# every flavour explicitly.
_ver = meson.project_version()
urcu_common_dep = urcu.dependency('urcu-common')

# external_project emits -L/-l for link time but no runpath, so a
# build-tree binary would resolve liburcu-* through the loader cache
# (a distro copy without the fractal trie) instead of these freshly
# built libraries. Point a runpath at the subproject's install libdir,
# where external_project stages the shared objects (DESTDIR 'dist' under
# the subproject build dir, then prefix/libdir). NOTE: this is a
# build-tree path; an installed BIND additionally needs the subproject
# libraries installed and its own install_rpath.
_urcu_libdir = (meson.current_build_dir() / 'dist') + (
    get_option('prefix') / get_option('libdir')
)
_urcu_rpath = ['-Wl,-rpath,' + _urcu_libdir]

urcu_cds_dep = declare_dependency(
    version: _ver,
    dependencies: [urcu.dependency('urcu-cds'), urcu_common_dep],
    link_args: _urcu_rpath,
)
urcu_memb_dep = declare_dependency(
    version: _ver,
    dependencies: [urcu.dependency('urcu'), urcu_common_dep],
    link_args: _urcu_rpath,
)
urcu_mb_dep = declare_dependency(
    version: _ver,
    dependencies: [urcu.dependency('urcu-mb'), urcu_common_dep],
    link_args: _urcu_rpath,
)
urcu_bp_dep = declare_dependency(
    version: _ver,
    dependencies: [urcu.dependency('urcu-bp'), urcu_common_dep],
    link_args: _urcu_rpath,
)
urcu_qsbr_dep = declare_dependency(
    version: _ver,
    dependencies: [urcu.dependency('urcu-qsbr'), urcu_common_dep],
    link_args: _urcu_rpath,
)
