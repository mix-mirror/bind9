#!/bin/sh

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

set -e

git config tar.tar.xz.command "xz -c"
git fetch --unshallow --all --tags || /bin/true

UPSTREAM_VERSION=$(git describe | sed -e 's/^v//')
UPSTREAM_DIRECTORY="/build/bind9"
UPSTREAM_TARBALL="/build/bind9-${UPSTREAM_VERSION}.tar.xz"
UPSTREAM_BRANCH="$1"
DEBIAN_BRANCH="$2"

rm -rf "${UPSTREAM_DIRECTORY}"

git archive --format=tar.xz --output="${UPSTREAM_TARBALL}" HEAD
git clone https://salsa.debian.org/dns-team/bind9.git "${UPSTREAM_DIRECTORY}" -b "${DEBIAN_BRANCH}"
cd "${UPSTREAM_DIRECTORY}"
for branch in pristine-tar "${UPSTREAM_BRANCH}" "${DEBIAN_BRANCH}"; do
  git checkout "${branch}"
done
gbp pull
gbp import-orig --debian-branch="${DEBIAN_BRANCH}" --pristine-tar --upstream-branch="${UPSTREAM_BRANCH}" --upstream-version="${UPSTREAM_VERSION}" "${UPSTREAM_TARBALL}"
gbp pq import
gbp pq export --commit
gbp dch --debian-branch="${DEBIAN_BRANCH}" --upstream-branch="${UPSTREAM_BRANCH}" --auto --release --commit-msg="Update changelog for $UPSTREAM_VERSION release" --commit --spawn-editor=never

chown -R sbuild: "${UPSTREAM_DIRECTORY}"
