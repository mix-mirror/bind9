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

import nox

# default sessions to run
nox.options.sessions = ["mypy", "pylint", "ruff", "black", "clang_format", "unit_tests", "system_tests"]

# reuse virtual environment for all sessions
nox.options.reuse_venv = "always"

# use venv as the default virtual environment backend
nox.options.default_venv_backend = "venv"

# do not download missing Python interpreter
nox.options.download_python = "never"


# we need to do this only once per nox run
BIND_CONFIGURED=False
BIND_COMPILED=False


def install_test_deps(session):
    session.install("-r", "bin/tests/system/requirements.txt")

def configure_bind(session):
    global BIND_CONFIGURED
    if BIND_CONFIGURED:
        return
    
    session.run(
        "meson", "setup",
        "--reconfigure", "--libdir=lib",
        "-Dcmocka=enabled",  "-Ddeveloper=enabled",
        "-Dleak-detection=enabled", "-Doptimization=1", "-Dnamed-lto=thin",
        "build-nox", external=True
    )
    BIND_CONFIGURED = True

def compile_bind(session):
    global BIND_COMPILED
    if BIND_COMPILED:
        return
    
    session.run(
        "meson", "compile", "-C" "build-nox", "-j", "-1",
        external=True
    )
    BIND_COMPILED = True

@nox.session()
def pip_compile_test_deps(session):
    "Call pip-compile to generate requiremets.txt with pinned versions and digests"
    session.install("pip-tools")
    session.run(
        "pip-compile",
        "-o", "bin/tests/system/requirements.txt",
        "--generate-hashes",
        "bin/tests/system/requirements.in"
    )

@nox.session(python=False)
def unit_tests(session):
    "Run unittests"
    configure_bind(session)
    compile_bind(session)
    session.run("meson", "test", "-C", "build-nox")

@nox.session()
def system_tests(session):
    "Run python system tests"
    install_test_deps(session)
    configure_bind(session)
    compile_bind(session)
    session.run("pytest", "-n", "20", "bin/tests/system")

@nox.session()
def mypy(session):
    "Run mypy python check"
    install_test_deps(session)
    session.install("mypy")
    session.run("mypy", "bin/tests/system/isctest/")

@nox.session()
def pylint(session):
    "Run pylint"
    install_test_deps(session)
    session.install("pylint")
    session.install("-r", "doc/arm/requirements.txt")
    files = session.run(
        "git", "ls-files", "*.py",
        external=True, silent=True
    )
    session.run("pylint", *files.split())

@nox.session()
def black(session):
    "Run python black formatter check"
    session.install("black")
    files = session.run(
        "git", "ls-files", "*.py",
        external=True, silent=True
    )
    session.run("black", "--check", *files.split())

@nox.session()
def black_fix(session):
    "Apply python black formatter fixes"
    session.install("black")
    files = session.run(
        "git", "ls-files", "*.py",
        external=True, silent=True
    )
    session.run("black", *files.split())

@nox.session()
def ruff(session):
    "Run python ruff checks"
    session.install("ruff")
    session.run("ruff", "check")

@nox.session()
def ruff_fix(session):
    "Apply python run fixes"
    session.install("ruff")
    session.run("ruff", "check", "--fix")

@nox.session(python=False)
def clang_format(session):
    "Run clang-format check"
    files = session.run(
        "git", "ls-files", "*.c", "*.h",
        external=True, silent=True
    )
    session.run(
        "clang-format", "-style=file",
        "--dry-run", "--fail-on-incomplete-format", "--Werror",
        *files.split(),
        external=True
    )

@nox.session(python=False)
def clang_format_fix(session):
    "Apply clang-format fixes"
    files = session.run(
        "git", "ls-files", "*.c", "*.h",
        external=True, silent=True
    )
    session.run(
        "clang-format", "-style=file", "-i",
        *files.split(),
        external=True
    )
