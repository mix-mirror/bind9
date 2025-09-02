#!/usr/bin/env python

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


import json
import os
from pathlib import Path

# Heuristic to filter out non-behavioral flags (warnings, object linking, etc.)
COMPILER_FILTER = (
    "-W",
    "-fdiagnostics",
    "-include",
    "/",
)

LINKER_FILTER = (
    "-Wl,--end",
    "-Wl,--start",
    "-Wl,-rpath",
    "lib",
)

build_root = os.getenv("BIND_BUILD_ROOT")
if build_root is None:
    raise Exception("running outside meson?")  # pylint: disable=broad-exception-raised

# https://mesonbuild.com/IDE-integration.html#the-targets-section
intro_dependencies = Path(build_root) / "meson-info" / "intro-targets.json"
with intro_dependencies.open() as f:
    build_targets = json.load(f)

# https://mesonbuild.com/IDE-integration.html#target-sources
named = next(x for x in build_targets if x["name"] == "named")["target_sources"]

assert "compiler" in named[0]
compiler_args = " ".join(
    [x for x in named[0]["parameters"] if not x.startswith(COMPILER_FILTER)],
)

# https://mesonbuild.com/Release-notes-for-1-2-0.html#more-data-in-introspection-files
# meson_version (>=1.2.0) : intro-targets.json now includes dependencies, vs_module_defs, win_subsystem, and linker parameters.
linker_args = "unprobed"
if len(named) > 1:
    assert "linker" in named[1]
    linker_args = " ".join(
        [x for x in named[1]["parameters"] if not x.startswith(LINKER_FILTER)],
    )

print(
    f"""const char *named_compiler_args = "{compiler_args}";
const char *named_linker_args = "{linker_args}";
"""
)
