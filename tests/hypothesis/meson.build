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

if python.found() and protoc.found() and proto_dep.found()
    u16bitmap_proto_c = custom_target(
        'u16bitmap-protobuf-c',
        input: files('u16bitmap_server.proto'),
        output: ['u16bitmap_server.pb-c.c', 'u16bitmap_server.pb-c.h'],
        command: [
            protoc,
            '--proto_path=@CURRENT_SOURCE_DIR@',
            '--c_out=@OUTDIR@',
            '@INPUT@',
        ],
    )

    u16bitmap_proto_py = custom_target(
        'u16bitmap-protobuf-python',
        input: files('u16bitmap_server.proto'),
        output: 'u16bitmap_server_pb2.py',
        command: [
            protoc,
            '--proto_path=@CURRENT_SOURCE_DIR@',
            '--python_out=@OUTDIR@',
            '@INPUT@',
        ],
    )

    u16bitmap_server = executable(
        'u16bitmap_server',
        files('u16bitmap_server.c'),
        u16bitmap_proto_c,
        build_by_default: false,
        install: false,
        dependencies: [
            libisc_dep,
            proto_dep,
        ],
    )

    u16bitmap_env = environment()
    u16bitmap_env.set('U16BITMAP_SERVER', u16bitmap_server.full_path())
    u16bitmap_env.set('PYTHONPATH', meson.current_build_dir())

    test(
        'u16bitmap',
        python,
        args: files('u16bitmap.py'),
        depends: [u16bitmap_server, u16bitmap_proto_py],
        env: u16bitmap_env,
        suite: ['hypothesis'],
        timeout: 300,
        workdir: meson.current_source_dir(),
    )
endif
