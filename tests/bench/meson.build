# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0.  If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

bench_dependencies = [
    libisc_dep,
    libdns_dep,
    libns_dep,
    libtest_dep,
]

crypto_mb_dep = null_dep
if bench_crypto_mb_opt.enabled()
    cmake = import('cmake')
    crypto_mb_options = cmake.subproject_options()
    crypto_mb_options.add_cmake_defines(
        {
            'ARCH': 'intel64',
            'BUILD_EXAMPLES': false,
            # The upstream project uses this switch to omit its test trees. It
            # does not enable clang-tidy unless the compiler is Clang.
            'CRYPTO_USE_CLANG_TIDY': true,
        },
    )
    # Intel overwrites CMAKE_C_FLAGS_DEBUG with -O0 after CMake has processed
    # user flags.  Meson's imported-target override is appended last.
    crypto_mb_options.append_compile_args(
        'c', '-O3', '-g', '-fno-omit-frame-pointer',
    )
    crypto_mb_project = cmake.subproject(
        'cryptography-primitives',
        options: crypto_mb_options,
    )
    crypto_mb_dep = declare_dependency(
        compile_args: '-DHAVE_CRYPTO_MB=1',
        dependencies: crypto_mb_project.dependency('crypto_mb_s'),
    )
endif

foreach bench : [
    'ascii',
    'compress',
    'iterated_hash',
    'load-names',
    'nsec3-full-rebuild',
    'qp-dump',
    'qplookups',
    'qpmulti',
    'siphash',
]
    executable(
        bench,
        files(fs.replace_suffix(bench, '.c')),
        export_dynamic: true,
        install: false,
        sources: default_sanitize_options,
        dependencies: bench_dependencies,
    )
endforeach

if bench_crypto_mb_opt.enabled()
    executable(
        'nsec3-full-mb8',
        files('nsec3-full-mb8.c'),
        export_dynamic: true,
        install: false,
        sources: default_sanitize_options,
        dependencies: bench_dependencies + crypto_mb_dep,
    )
endif

executable(
    'dns_name_fromwire',
    files(
        'dns_name_fromwire.c',
        meson.project_source_root() / 'fuzz' / 'old.c',
    ),
    export_dynamic: true,
    include_directories: '..' / '..' / 'fuzz',
    install: false,
    sources: default_sanitize_options,
    dependencies: [
        libisc_dep,
        libdns_dep,
        libns_dep,
        libtest_dep,
    ],
)
