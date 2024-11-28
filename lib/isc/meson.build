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

isc_inc = include_directories('include')

# Use sourceset to add conditional files
# https://mesonbuild.com/SourceSet-module.html
isc_srcset = ss.source_set()

subdir('netmgr')
subdir('include' / 'isc')

isc_srcset.add(
    files(
        'ascii.c',
        'assertions.c',
        'async.c',
        'backtrace.c',
        'base32.c',
        'base64.c',
        'commandline.c',
        'condition.c',
        'counter.c',
        'crypto.c',
        'dir.c',
        'entropy.c',
        'errno.c',
        'errno2result.c',
        'error.c',
        'file.c',
        'fips.c',
        'getaddresses.c',
        'hash.c',
        'hashmap.c',
        'heap.c',
        'helper.c',
        'hex.c',
        'histo.c',
        'hmac.c',
        'ht.c',
        'httpd.c',
        'interfaceiter.c',
        'iterated_hash.c',
        'lex.c',
        'lib.c',
        'log.c',
        'loop.c',
        'managers.c',
        'md.c',
        'mem.c',
        'meminfo.c',
        'mutex.c',
        'mutexblock.c',
        'net.c',
        'netaddr.c',
        'netscope.c',
        'nonce.c',
        'openssl_shim.c',
        'os.c',
        'parseint.c',
        'picohttpparser.c',
        'portset.c',
        'proxy2.c',
        'quota.c',
        'radix.c',
        'random.c',
        'ratelimiter.c',
        'regex.c',
        'region.c',
        'result.c',
        'safe.c',
        'serial.c',
        'signal.c',
        'sockaddr.c',
        'stats.c',
        'stdio.c',
        'stdtime.c',
        'string.c',
        'symtab.c',
        'syslog.c',
        'thread.c',
        'tid.c',
        'time.c',
        'timer.c',
        'tls.c',
        'tm.c',
        'url.c',
        'utf8.c',
        'uv.c',
        'work.c',
        'xml.c',
    ),
)

isc_probed_src = [dtrace_header.process('probes.d'), files('job.c')]
if not config.has('USE_PTHREAD_RWLOCK')
    isc_probed_src += files('rwlock.c')
endif

isc_probe_target = static_library(
    'isc-probe-target',
    isc_probed_src,
    build_by_default: false,
    dependencies: [uv_dep, urcu_dep],
    include_directories: isc_inc,
).extract_all_objects(recursive: false)

isc_srcset.add(
    custom_target(
        'isc-probe',
        input: ['probes.d', isc_probe_target],
        output: 'probes.o',
        command: [
            dtrace,
            '-G',
            '-o', '@OUTPUT@',
            '-s', '@INPUT@',
        ],
    ),
)

isc_srcconf = isc_srcset.apply(config, strict: false)

libisc = shared_library(
    'isc',
    isc_srcconf.sources(),
    objects: isc_probe_target,
    install: true,
    include_directories: isc_inc,
    dependencies: [
        m_dep,
        openssl_dep,
        thread_dep,
        urcu_dep,
        uv_dep,

        jemalloc_dep,
        json_c_dep,
        xml2_dep,
        zlib_dep,

        isc_srcconf.dependencies(),
    ],
)

libisc_dep = declare_dependency(
    link_with: libisc,
    include_directories: isc_inc,
    dependencies: [
        openssl_dep,
        thread_dep,
        urcu_dep,
        uv_dep,

        jemalloc_dep,
    ],
)
