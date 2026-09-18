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
    nox -s doctest                     run the doctests of the system test
                                       library
    nox -s ci_doctest                  run the doctests the way the CI job does
    nox -s build_asan                  build with ASAN and UBSAN
    nox -s system_tests_asan -- -k x   run the system tests against that build
    nox -s docs                        build the ARM and the manual pages
    nox -s doc_misc                    regenerate the grammar files in doc/misc
    nox -s docs_pdf                    build the ARM as PDF (needs TeX Live)

The Python dependencies are declared as dependency groups in pyproject.toml
and pinned with pip-compile in bin/tests/system/requirements.txt (system
tests) and requirements-lint.txt (linters); the sessions install the pinned
files into their virtual environments.  After changing the dependency groups
run `nox -s pip_compile` (`-- --upgrade` to bump the pins).  The pins are
generated with the oldest supported Python so that they cover its extra
dependencies: pip's hash checking refuses anything that is not pinned.

The documentation sessions install doc/arm/requirements.txt, the Sphinx
pins that Read the Docs builds with, into their own build directory (the
docs_setup session): meson records the sphinx-build it finds at the first
setup, so the directory of the build session would keep whatever the system
had.

The build directories are configured with the meson machine files the CI
build jobs use (ci/*.ini): ci/common.ini, the overlay of the platform the
build runs on when CI has one for it, and the sanitizer's; the session
logs which ones it applied.

Environment variables:

    NOX_BUILD_DIR              build directory (default: build-nox)
    NOX_ASAN_BUILD_DIR         build directory of build_asan (default:
                               NOX_BUILD_DIR with -asan appended)
    NOX_CC                     compiler, gcc (default) or clang; CI builds
                               with clang on Debian trixie only
    NOX_SKIP_BUILD=1           use the build directory as it is, do not
                               configure or compile (CI gets it from the
                               build job)
    NOX_DOCS_BUILD_DIR         build directory of the documentation sessions
                               (default: NOX_BUILD_DIR with -docs appended);
                               always configured, NOX_SKIP_BUILD does not
                               apply to it
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

import glob
import os
import platform
import re
import shutil
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
ASAN_BUILD_DIR = os.environ.get("NOX_ASAN_BUILD_DIR", BUILD_DIR + "-asan")
DOCS_BUILD_DIR = os.environ.get("NOX_DOCS_BUILD_DIR", BUILD_DIR + "-docs")
SKIP_BUILD = os.environ.get("NOX_SKIP_BUILD") == "1"
CC = os.environ.get("NOX_CC", "gcc")
CLANG_FORMAT = os.environ.get("CLANG_FORMAT", "clang-format")

QA_REPO = "https://gitlab.isc.org/isc-projects/bind9-qa.git"
QA_DIR = os.environ.get("NOX_BIND9_QA_DIR", "bind9-qa")
QA_REF = os.environ.get("NOX_BIND9_QA_REF", "main")

TEST_REQUIREMENTS = "bin/tests/system/requirements.txt"
LINT_REQUIREMENTS = "requirements-lint.txt"
# the Sphinx pins Read the Docs builds the ARM with
DOCS_REQUIREMENTS = "doc/arm/requirements.txt"

# the named.conf and rndc grammar files the ARM is built from; generated by
# cfg_test and committed, the doc_misc session checks that they are current
DOC_MISC_DIR = "doc/misc"

# what mandoc is allowed to say about the generated manual pages (the CI
# docs job filters the same messages)
MANDOC_TOLERATED = (
    "skipping paragraph macro. sp after",
    "unknown font, skipping request. ft C",
    "input text line longer than 80 bytes",
)

SYSTEM_TEST_DIR = "bin/tests/system"
# where the CI after_script looks for the pytest output
PYTEST_LOG = os.path.join(SYSTEM_TEST_DIR, "pytest.out.txt")

# pip skips the packages that the system already provides in the pinned
# version, so only the missing or differing ones get downloaded
if os.environ.get("NOX_SYSTEM_SITE_PACKAGES") == "1":
    VENV_PARAMS = ["--system-site-packages"]
else:
    VENV_PARAMS = []


def build_var(name, build_dir=BUILD_DIR):
    """A variable recorded by the build for the system tests, if built yet."""
    path = os.path.join(build_dir, "bin/tests/system/isctest/vars/.build_vars", name)
    try:
        with open(path, encoding="utf-8") as f:
            return f.read().strip()
    except FileNotFoundError:
        return None


def build_python(build_dir=BUILD_DIR):
    """The interpreter the build found, to run the system tests with."""
    interpreter = build_var("PYTHON", build_dir)
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
    """The tracked files matching the patterns.

    The linters run on the tracked files only, so that build directories,
    checkouts of other repositories and other stray files in the tree do
    not get linted.
    """
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


def os_release():
    """The fields of /etc/os-release, empty where there is none."""
    fields = {}
    try:
        with open("/etc/os-release", encoding="utf-8") as f:
            for line in f:
                key, sep, value = line.strip().partition("=")
                if sep:
                    fields[key] = value.strip('"')
    except FileNotFoundError:
        pass
    return fields


def platform_overlay(release):
    """The name of the ci/*.ini overlay for the platform `release` describes.

    The names are those of the CI build jobs' machine files, one per image
    (see .gitlab-ci.yml); Fedora and Debian trixie on amd64 are the base
    platforms, which need none.  A name that has no file falls back to none
    so that the build works on platforms CI does not cover.
    """
    distro = release.get("ID", platform.system().lower())
    version = release.get("VERSION_ID", platform.release()).partition(".")[0]
    codename = release.get("VERSION_CODENAME", "")
    if distro in ("almalinux", "freebsd"):
        name = distro + version
    elif distro == "opensuse-tumbleweed":
        name = "tumbleweed"
    elif distro == "debian":
        if "/sid" in release.get("PRETTY_NAME", ""):
            name = "sid"
        elif codename == "trixie" and platform.machine() in ("i386", "i686"):
            name = "trixie386"
        else:
            name = codename
    elif distro == "ubuntu":
        name = codename
    else:
        name = distro
    if os.path.exists(machine_file(name)):
        return name
    return None


def machine_file(name):
    """The path of the ci/*.ini machine file `name`."""
    return os.path.join("ci", f"{name}.ini")


def machine_files(session, sanitizer=None):
    """The meson machine files for a build on this platform, in meson order.

    Later files override earlier ones: the common options, the platform
    overlay, the sanitizer's, then the compiler's, like the CI build jobs
    pass them.
    """
    release = os_release()
    names = ["common"]
    overlay = platform_overlay(release)
    if overlay:
        names.append(overlay)
    else:
        session.log(
            "no ci/*.ini overlay for %s %s, using the base options",
            release.get("ID", platform.system()),
            release.get("VERSION_ID", platform.release()),
        )
    if sanitizer:
        names.append(sanitizer)
    if CC == "clang":
        if release.get("VERSION_CODENAME") != "trixie":
            session.error("CI builds with clang on Debian trixie only (NOX_CC)")
        names.append("clang-trixie")
        if sanitizer:
            names.append("clang-sanitizer")
    elif CC != "gcc":
        session.error(f"NOX_CC={CC}: the machine files cover gcc and clang")
    return [machine_file(name) for name in names]


def meson_setup(session, build_dir, sanitizer=None):
    """Configure `build_dir` with the machine files for this platform."""
    files = machine_files(session, sanitizer)
    session.log("meson machine files: %s", " ".join(files))
    args = []
    for path in files:
        args += ["--native-file", path]
    session.run("meson", "setup", "--reconfigure", *args, build_dir, external=True)


def meson_compile(session, build_dir):
    """Compile BIND and the system test helpers in `build_dir`."""
    session.run("meson", "compile", "-C", build_dir, "-j", "-1", external=True)
    # not a default target, but the system tests need it
    session.run(
        "meson", "compile", "-C", build_dir, "system-test-dependencies", external=True
    )


# The build runs without a virtual environment so that meson does not record
# the venv python as the interpreter for the system tests.
@nox.session(python=False)
def configure(session):
    "Configure the build directory"
    if SKIP_BUILD:
        return
    meson_setup(session, BUILD_DIR)


@nox.session(python=False, requires=["configure"])
def build(session):
    "Compile BIND in the build directory"
    if SKIP_BUILD:
        return
    meson_compile(session, BUILD_DIR)


@nox.session(python=False)
def build_asan(session):
    "Configure and compile BIND with ASAN and UBSAN in the ASAN build directory"
    if SKIP_BUILD:
        return
    meson_setup(session, ASAN_BUILD_DIR, sanitizer="asan")
    meson_compile(session, ASAN_BUILD_DIR)


@nox.session(python=False, requires=["build"])
def unit_tests(session):
    "Run the unit tests"
    session.run("meson", "test", "-C", BUILD_DIR, *session.posargs, external=True)


@pysession(python=build_python(), requires=["build"])
def system_tests(session):
    "Run the system tests (extra arguments are passed to pytest)"
    install(session, TEST_REQUIREMENTS)
    run_system_tests(session, *session.posargs)


@pysession(python=build_python(ASAN_BUILD_DIR), requires=["build_asan"])
def system_tests_asan(session):
    "Run the system tests against the ASAN build (extra arguments go to pytest)"
    install(session, TEST_REQUIREMENTS)
    run_system_tests(session, *session.posargs)


def run_doctest(session, *args):
    """Run the doctests of the system test library.

    The library reads the build variables, which the system-test-init
    target writes into the source tree; the target does not compile
    anything.
    """
    if not SKIP_BUILD:
        session.run(
            "meson", "compile", "-C", BUILD_DIR, "system-test-init", external=True
        )
    # from the system test directory, like the system tests: `python -m
    # pytest` puts the current directory first on sys.path, and from inside
    # isctest its hypothesis subpackage would shadow the real one
    with session.chdir(SYSTEM_TEST_DIR):
        session.run(
            python(session),
            "-m",
            "pytest",
            "--noconftest",
            "--doctest-modules",
            *args,
            "isctest",
        )


@pysession(python=build_python(), requires=["configure"])
def doctest(session):
    "Run the doctests of the system test library (extra arguments go to pytest)"
    install(session, TEST_REQUIREMENTS)
    run_doctest(session, *session.posargs)


@pysession(python=build_python(), requires=["configure"])
def ci_doctest(session):
    "Run the doctests the way the CI job does (extra arguments go to pytest)"
    install(session, TEST_REQUIREMENTS)
    checkout_bind9_qa(session)
    # the JUnit post-processing runs, and validates junit.xml, even when
    # the doctests fail
    junit_pytest = "junit_doctest.xml"
    passed = attempt(
        run_doctest,
        session,
        f"--junit-xml={os.path.abspath(junit_pytest)}",
        *session.posargs,
    )
    postprocess_junit(session, "junit.xml", junit_pytest)
    if not passed:
        session.error("the doctests failed")


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
    session.run("mypy", *git_ls_files(session, "bin/tests/system/isctest/*.py"))


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
    session.run("ruff", "check", *git_ls_files(session, "*.py"))


@pysession
def ruff_fix(session):
    "Apply the ruff fixes"
    install(session, LINT_REQUIREMENTS)
    session.run("ruff", "check", "--fix", *git_ls_files(session, "*.py"))


@pysession
def vulture(session):
    "Look for dead Python code with vulture"
    install(session, LINT_REQUIREMENTS)
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


def docs_sphinx_build(session):
    """The sphinx-build meson has to record for the docs build directory.

    None when the system one is meant (`nox --no-venv`).
    """
    if session.venv_backend == "none":
        return None
    sphinx_build = os.path.join(session.bin, "sphinx-build")
    if os.path.exists(sphinx_build):
        return os.path.abspath(sphinx_build)
    # NOX_SYSTEM_SITE_PACKAGES=1 and the system ships the pinned Sphinx: pip
    # installed nothing, the system script imports the pinned version
    return shutil.which("sphinx-build")


def docs_machine_file(session, sphinx_build):
    """Write the meson machine file that names `sphinx_build`.

    meson re-reads the file on every reconfigure, so it lives at a stable
    path and gets rewritten every time.
    """
    path = os.path.join(session.create_tmp(), "sphinx.ini")
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"[binaries]\nsphinx-build = '{sphinx_build}'\n")
    return path


def docs_build_dir_uses(sphinx_build):
    """Whether the docs build directory runs `sphinx_build`, if configured.

    meson looks programs up at the first setup only; a reconfigure keeps the
    recorded result, so a directory set up with another sphinx-build has to
    be wiped.
    """
    try:
        with open(os.path.join(DOCS_BUILD_DIR, "build.ninja"), encoding="utf-8") as f:
            return sphinx_build in f.read()
    except FileNotFoundError:
        return True


@pysession
def docs_setup(session):
    "Configure the documentation build directory with the pinned Sphinx"
    install(session, DOCS_REQUIREMENTS)
    sphinx_build = docs_sphinx_build(session)
    mode = "--reconfigure"
    setup_args = []
    if sphinx_build is not None:
        setup_args = ["--native-file", docs_machine_file(session, sphinx_build)]
        if not docs_build_dir_uses(sphinx_build):
            session.log(
                f"{DOCS_BUILD_DIR} was configured with another sphinx-build, wiping it"
            )
            mode = "--wipe"
    session.run(
        "meson",
        "setup",
        mode,
        "-Ddoc=enabled",
        *setup_args,
        DOCS_BUILD_DIR,
        external=True,
    )


@nox.session(python=False, requires=["docs_setup"])
def doc_misc(session):
    "Regenerate the grammar files in doc/misc; fail if they were out of date"
    session.run("meson", "compile", "-C", DOCS_BUILD_DIR, "doc-misc", external=True)
    generated = os.path.join(DOCS_BUILD_DIR, DOC_MISC_DIR)
    files = [os.path.join(generated, name) for name in ("options", "rndc.grammar")]
    files += sorted(glob.glob(os.path.join(generated, "*.zoneopt")))
    for path in files:
        shutil.copy(path, DOC_MISC_DIR)
    # untracked files included: a new zone type is a new .zoneopt file
    changed = session.run(
        "git", "status", "--porcelain", "--", DOC_MISC_DIR, external=True, silent=True
    )
    if changed.strip():
        session.run("git", "--no-pager", "diff", "--", DOC_MISC_DIR, external=True)
        session.error(
            f"the grammar files in {DOC_MISC_DIR} were out of date and have been"
            " regenerated; review and commit them"
        )


def mandoc_lint(session, mandir):
    """Fail on what mandoc says about the manual pages, tolerated messages aside."""
    if shutil.which("mandoc") is None:
        session.warn(
            "mandoc not found: skipping the manual page lint the CI docs job runs"
        )
        return
    pages = sorted(glob.glob(os.path.join(mandir, "man[0-9]", "*.[0-9]")))
    if not pages:
        session.error(f"no manual pages found in {mandir}")
    # mandoc exits non-zero whenever it has something to say; the messages decide
    output = session.run(
        "mandoc",
        "-T",
        "lint",
        *pages,
        external=True,
        silent=True,
        success_codes=list(range(7)),
    )
    messages = [
        line
        for line in output.splitlines()
        if line.strip() and not any(tolerated in line for tolerated in MANDOC_TOLERATED)
    ]
    if messages:
        print("\n".join(messages), flush=True)
        session.error("mandoc reported problems in the manual pages")


@nox.session(python=False, requires=["docs_setup"])
def docs(session):
    "Build the ARM (HTML and EPUB) and the manual pages like the CI docs job"
    session.run(
        "meson",
        "compile",
        "-C",
        DOCS_BUILD_DIR,
        "arm",
        "arm-epub",
        "man",
        external=True,
    )
    mandoc_lint(session, os.path.join(DOCS_BUILD_DIR, "man"))


@nox.session(python=False, requires=["docs_setup"])
def docs_pdf(session):
    "Build the ARM as PDF (needs TeX Live with xelatex and latexmk)"
    missing = [tool for tool in ("xelatex", "latexmk") if shutil.which(tool) is None]
    if missing:
        session.error(f"{', '.join(missing)} not found: the PDF needs TeX Live")
    session.run("meson", "compile", "-C", DOCS_BUILD_DIR, "arm-pdf", external=True)
    session.log(
        f"the PDF is {os.path.join(DOCS_BUILD_DIR, 'arm-pdf', 'latex', 'Bv9ARM.pdf')}"
    )
