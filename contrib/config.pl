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

# Set the chroot mode to be unshare.
$chroot_mode = 'unshare';

# Build Architecture: all packages; this is the same as passing `-A` to sbuild.
$build_arch_all = 1;

# Build the source package in addition to the other requested build artifacts; this is the same as passing `-s` to sbuild.
$build_source = 1;

# Produce a .changes file suitable for a source-only upload; this is the same as passing `--source-only-changes` to sbuild.
$source_only_changes = 1;

## Run lintian after every build (in the same chroot as the build); use --no-run-lintian to override.
$run_lintian = 0;

## Run autopkgtest after every build (in a new, clean, chroot); use --no-run-autopkgtest to override.
$run_autopkgtest = 0;

## Run piuparts after every build (in a new, temporary, chroot); use --no-run-piuparts to override.
# this does not work in bookworm
$run_piuparts = 0;

# Keep the generated tarballs
$unshare_mmdebstrap_keep_tarball = 0;
