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

"""
Developer entry point for running the checks and tests locally.

    nox -l                             list sessions
    nox                                run the default sessions
    nox -s system_tests -- -k dnssec   pass extra arguments to pytest
    nox -s ci_system_tests             run the system tests the way the CI
                                       job does (see the session)

The Python dependencies are declared as dependency groups in pyproject.toml
and pinned with pip-compile in bin/tests/system/requirements.txt (system
tests) and requirements-lint.txt (linters); the sessions install the pinned
files into their virtual environments.  After changing the dependency groups
run `nox -s pip_compile` (`-- --upgrade` to bump the pins).  The pins are
generated with the oldest supported Python so that they cover its extra
dependencies: pip's hash checking refuses anything that is not pinned.

Environment variables:

    NOX_BUILD_DIR              build directory (default: build-nox)
    NOX_SKIP_BUILD=1           use the build directory as it is, do not
                               configure or compile (CI gets it from the
                               build job)
    TEST_PARALLEL_JOBS         number of pytest workers (default: 20)
    NOX_BIND9_QA_DIR           bind9-qa checkout used by ci_system_tests
                               (default: bind9-qa, next to this file)
    NOX_BIND9_QA_REF           branch, tag or commit of bind9-qa to check
                               out (default: main)
    CLANG_FORMAT               clang-format executable (default: clang-format)
    NOX_SYSTEM_SITE_PACKAGES=1 let the virtual environments see the packages
                               installed on the system and install only
                               those that are missing or differ from the
                               pinned versions (meant for the CI images,
                               which ship the packages)

`nox --no-venv` runs the tools installed on the system without installing
anything.
"""

import os
import re
import sys

import nox
import nox.command

# session dependencies (`requires`) need this version
nox.needs_version = ">=2025.2.9"

nox.options.sessions = [
    "mypy",
    "pylint",
    "ruff",
    "black",
    "vulture",
    "clang_format",
    "unit_tests",
    "system_tests",
]
nox.options.reuse_venv = "always"
# virtualenv (unlike venv) does not need ensurepip, which the distribution
# python packages often lack
nox.options.default_venv_backend = "virtualenv"

BUILD_DIR = os.environ.get("NOX_BUILD_DIR", "build-nox")
SKIP_BUILD = os.environ.get("NOX_SKIP_BUILD") == "1"
CLANG_FORMAT = os.environ.get("CLANG_FORMAT", "clang-format")

QA_REPO = "https://gitlab.isc.org/isc-projects/bind9-qa.git"
QA_DIR = os.environ.get("NOX_BIND9_QA_DIR", "bind9-qa")
QA_REF = os.environ.get("NOX_BIND9_QA_REF", "main")

TEST_REQUIREMENTS = "bin/tests/system/requirements.txt"
LINT_REQUIREMENTS = "requirements-lint.txt"

SYSTEM_TEST_DIR = "bin/tests/system"
# where the CI after_script looks for the pytest output
PYTEST_LOG = os.path.join(SYSTEM_TEST_DIR, "pytest.out.txt")

# pip skips the packages that the system already provides in the pinned
# version, so only the missing or differing ones get downloaded
if os.environ.get("NOX_SYSTEM_SITE_PACKAGES") == "1":
    VENV_PARAMS = ["--system-site-packages"]
else:
    VENV_PARAMS = []


def build_var(name):
    """A variable recorded by the build for the system tests, if built yet."""
    path = os.path.join(BUILD_DIR, "bin/tests/system/isctest/vars/.build_vars", name)
    try:
        with open(path, encoding="utf-8") as f:
            return f.read().strip()
    except FileNotFoundError:
        return None


def build_python():
    """The interpreter the build found, to run the system tests with."""
    interpreter = build_var("PYTHON")
    if interpreter and os.access(interpreter, os.X_OK):
        return interpreter
    return None


def pysession(*args, **kwargs):
    """nox.session for the sessions that need the Python dependencies"""
    return nox.session(*args, venv_params=VENV_PARAMS, **kwargs)


def install(session, requirements):
    """Install a pinned requirements file into the session venv."""
    if session.venv_backend == "none":
        return  # `nox --no-venv`: use whatever is installed on the system
    session.install("-r", requirements)


def python(session):
    """The Python interpreter of the session"""
    if session.venv_backend == "none":
        return sys.executable
    return "python"


def git_ls_files(session, *patterns):
    return session.run("git", "ls-files", *patterns, external=True, silent=True).split()


def qa_git(session, *args, **kwargs):
    """Run git in the bind9-qa checkout."""
    return session.run("git", "-C", QA_DIR, *args, external=True, **kwargs)


def qa_rev_parse(session, rev):
    """The commit `rev` names in the bind9-qa checkout, or None if none."""
    out = qa_git(
        session,
        "rev-parse",
        "--verify",
        "--quiet",
        rev,
        silent=True,
        success_codes=[0, 1],
    )
    return out.strip() or None


def checkout_bind9_qa(session):
    """Clone bind9-qa into QA_DIR if needed and check out QA_REF."""
    # init + fetch instead of clone so that a commit works as the ref the
    # same way a branch does (GitLab serves any reachable commit)
    if not os.path.isdir(os.path.join(QA_DIR, ".git")):
        session.run("git", "init", "--quiet", QA_DIR, external=True)
        qa_git(session, "remote", "add", "origin", QA_REPO)
    head = qa_rev_parse(session, "HEAD")
    if re.fullmatch("[0-9a-f]{40}", QA_REF) and head == QA_REF:
        return
    qa_git(session, "fetch", "--depth", "1", "origin", QA_REF)
    if qa_rev_parse(session, "FETCH_HEAD") != head:
        qa_git(session, "checkout", "--quiet", "--detach", "FETCH_HEAD")


def setup_interfaces(session):
    """Bring up the loopback addresses the system tests bind to."""
    script = os.path.join(BUILD_DIR, "bin/tests/system/ifconfig.sh")
    command = ["sh", "-x", script, "up"]
    if os.geteuid() != 0:
        command.insert(0, "sudo")
    session.run(*command, external=True)


def attempt(func, *args, **kwargs):
    """Call a function that runs commands; return whether they all succeeded."""
    try:
        func(*args, **kwargs)
    except nox.command.CommandFailed:
        return False
    return True


# A `tee` for session.run: the output has to reach both the terminal (or
# the CI job log) and a file, and the exit status has to survive the pipe,
# which a shell pipeline only guarantees with bash's pipefail; not every
# CI image has bash.  Only stdout is captured, like `| tee`.
TEE = """
import subprocess
import sys

with open(sys.argv[1], "wb") as log, subprocess.Popen(
    sys.argv[2:], stdout=subprocess.PIPE
) as proc:
    for line in proc.stdout:
        sys.stdout.buffer.write(line)
        sys.stdout.buffer.flush()
        log.write(line)
sys.exit(proc.returncode)
"""


def tee(session, logfile, *command, **kwargs):
    """session.run `command`, copying its stdout to `logfile`."""
    session.run(python(session), "-c", TEE, logfile, *command, **kwargs)


def pytest_command(session, *args):
    """The pytest command line for the system tests, with the default -n."""
    args = list(args)
    if not any(arg.startswith(("-n", "--numprocesses")) for arg in args):
        args = ["-n", os.environ.get("TEST_PARALLEL_JOBS", "20"), *args]
    return [python(session), "-m", "pytest", *args]


def run_system_tests(session, *args, log=None):
    """Run pytest in the system test directory, copying its output to `log`.

    `log` is relative to the source root, like the other paths here.
    """
    if log is not None:
        log = os.path.abspath(log)
    # run from the system test directory like the README describes so that
    # test directories can be given as arguments (`-- rrchecker`)
    with session.chdir(SYSTEM_TEST_DIR):
        command = pytest_command(session, *args)
        if log is None:
            session.run(*command)
        else:
            tee(session, log, *command)


def oom_check(session):
    """Fail if the kernel OOM killer ran (see the script)."""
    session.run("sh", "util/oom-check.sh", external=True)


def postprocess_junit(session, output, *inputs):
    """Merge JUnit files into `output` in the form GitLab displays best."""
    session.run(
        python(session),
        os.path.join(QA_DIR, "ci/postprocess_junit_files.py"),
        *inputs,
        "--output",
        output,
    )


def display_pytest_failures(log):
    """Print the FAILURES and ERRORS sections of the pytest output again.

    They are what one looks for in a long log, so they go last.
    """
    with open(log, encoding="utf-8", errors="replace") as f:
        lines = f.read().splitlines()
    for section in ("FAILURES", "ERRORS"):
        inside = False
        for line in lines:
            if re.fullmatch(f"=+ {section} =+", line):
                inside = True
            elif re.fullmatch("=+ .* =+", line):
                inside = False
            elif inside:
                # nox logs to stderr; keep the order when stdout is a pipe
                print(line, flush=True)


def check_grep_warnings(session, log):
    """Fail if a test script tripped a grep warning (a broken pattern)."""
    with open(log, encoding="utf-8", errors="replace") as f:
        if "grep: warning:" in f.read():
            session.error(f"grep printed a warning, see {log}")


@nox.session(python="3.10")
def pip_compile(session):
    "Pin the dependency groups of pyproject.toml (`-- --upgrade` to bump the pins)"
    session.install("pip-tools", "dependency-groups")
    tmp = session.create_tmp()
    for group, output in (("test", TEST_REQUIREMENTS), ("lint", LINT_REQUIREMENTS)):
        # pip-compile does not read dependency groups itself
        source = os.path.join(tmp, f"{group}.in")
        session.run("dependency-groups", "-f", "pyproject.toml", "-o", source, group)
        session.run(
            "pip-compile",
            "--generate-hashes",
            "--strip-extras",
            "--no-header",
            "--no-annotate",
            "--output-file",
            output,
            *session.posargs,
            source,
        )
        with open(output, encoding="utf-8") as f:
            pins = f.read()
        with open(output, "w", encoding="utf-8") as f:
            f.write(
                f"# Generated by `nox -s pip_compile` from the {group!r} dependency\n"
                "# group in pyproject.toml.  Do not edit.\n"
            )
            f.write(pins)


# The build runs without a virtual environment so that meson does not record
# the venv python as the interpreter for the system tests.
@nox.session(python=False)
def build(session):
    "Configure and compile BIND in the build directory"
    if SKIP_BUILD:
        return
    session.run(
        "meson",
        "setup",
        "--reconfigure",
        "--libdir=lib",
        "-Dcmocka=enabled",
        "-Ddeveloper=enabled",
        "-Dleak-detection=enabled",
        "-Doptimization=1",
        "-Dnamed-lto=thin",
        BUILD_DIR,
        external=True,
    )
    session.run("meson", "compile", "-C", BUILD_DIR, "-j", "-1", external=True)


@nox.session(python=False, requires=["build"])
def unit_tests(session):
    "Run the unit tests"
    session.run("meson", "test", "-C", BUILD_DIR, *session.posargs, external=True)


@pysession(python=build_python(), requires=["build"])
def system_tests(session):
    "Run the system tests (extra arguments are passed to pytest)"
    install(session, TEST_REQUIREMENTS)
    run_system_tests(session, *session.posargs)


@pysession(python=build_python(), requires=["build"])
def ci_system_tests(session):
    "Run the system tests the way the CI job does (extra arguments go to pytest)"
    install(session, TEST_REQUIREMENTS)
    checkout_bind9_qa(session)
    setup_interfaces(session)
    # A failure is reported only after the OOM check and the JUnit
    # post-processing so that junit.xml is produced, and validated, even
    # when the tests fail.
    junit_pytest = "junit_pytest.xml"
    passed = attempt(
        run_system_tests,
        session,
        f"--junit-xml={os.path.abspath(junit_pytest)}",
        *session.posargs,
        log=PYTEST_LOG,
    )
    no_oom = attempt(oom_check, session)
    postprocess_junit(session, "junit.xml", junit_pytest)
    display_pytest_failures(PYTEST_LOG)
    if not (passed and no_oom):
        session.error("the system tests failed")
    check_grep_warnings(session, PYTEST_LOG)


@pysession
def mypy(session):
    "Run mypy on the system test library"
    install(session, LINT_REQUIREMENTS)
    session.run("mypy", "bin/tests/system/isctest/")


@pysession
def pylint(session):
    "Run pylint"
    install(session, LINT_REQUIREMENTS)
    # the pylint plugins in doc/arm/_ext import sphinx
    install(session, "doc/arm/requirements.txt")
    session.run("pylint", *git_ls_files(session, "*.py"))


@pysession
def black(session):
    "Check the Python formatting with black"
    install(session, LINT_REQUIREMENTS)
    session.run("black", "--check", *git_ls_files(session, "*.py"))


@pysession
def black_fix(session):
    "Reformat the Python files with black"
    install(session, LINT_REQUIREMENTS)
    session.run("black", *git_ls_files(session, "*.py"))


@pysession
def ruff(session):
    "Run ruff"
    install(session, LINT_REQUIREMENTS)
    session.run("ruff", "check")


@pysession
def ruff_fix(session):
    "Apply the ruff fixes"
    install(session, LINT_REQUIREMENTS)
    session.run("ruff", "check", "--fix")


@pysession
def vulture(session):
    "Look for dead Python code with vulture"
    install(session, LINT_REQUIREMENTS)
    # restrict vulture to the tracked files so that stray build directories
    # do not get scanned
    session.run("vulture", *git_ls_files(session, "*.py"))


@nox.session(python=False)
def clang_format(session):
    "Check the C formatting with clang-format"
    session.run(
        CLANG_FORMAT,
        "-style=file",
        "--dry-run",
        "--fail-on-incomplete-format",
        "--Werror",
        *git_ls_files(session, "*.c", "*.h"),
        external=True,
    )


@nox.session(python=False)
def clang_format_fix(session):
    "Reformat the C files with clang-format"
    session.run(
        CLANG_FORMAT,
        "-style=file",
        "-i",
        *git_ls_files(session, "*.c", "*.h"),
        external=True,
    )
