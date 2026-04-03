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

from pathlib import Path

import shutil

import dns.name

from .kasp import Key
from .log import debug
from .run import EnvCmd
from .template import NS1, Nameserver, TemplateEngine, TrustAnchor
from .vars.algorithms import Algorithm

KEYDIR = "keys"


class Zone:
    """
    Zone providing zone file setup and signing operations.

    This is the operational counterpart to isctest.template.Zone, which is a
    plain data container for template rendering. Use isctest.template.zones()
    to convert a list of Zone instances into template data.
    """

    def __init__(
        self,
        name: str | dns.name.Name,
        ns: Nameserver,
        signed: bool = False,
        subdir: str | None = "zones",
        filepath_unsigned: Path | str | None = None,
        filepath_signed: Path | str | None = None,
        type: str = "primary",  # pylint: disable=redefined-builtin
    ) -> None:
        self.dname: dns.name.Name = (
            dns.name.from_text(name) if isinstance(name, str) else name
        )
        raw = self.dname.to_text()
        self.name: str = raw if raw == "." else raw.rstrip(".")
        self.basename: str = "root" if self.dname == dns.name.root else self.name
        self.ns = ns
        self.signed = signed
        self.subdir = subdir
        self.type = type

        prefix = f"{subdir}/" if subdir else ""
        self.filepath_unsigned: Path = Path(
            filepath_unsigned or f"{prefix}{self.basename}.db"
        )
        self.filepath_signed: Path = Path(
            filepath_signed or f"{prefix}{self.basename}.db.signed"
        )

        self.delegations: list[Zone] = []
        self.keys: list[Key] = []

    @property
    def filepath(self) -> Path:
        """Actual zone file — filepath_signed if signed, filepath_unsigned otherwise."""
        return self.filepath_signed if self.signed else self.filepath_unsigned

    def make_key(self, params: str = "", alg: Algorithm | None = None) -> Key:
        """Generate a DNSSEC key and return it without adding it to self.keys."""
        debug(f"{self.name}: generating key")
        keydir = Path(self.ns.name) / KEYDIR
        keydir.mkdir(exist_ok=True)
        if alg is None:
            alg = Algorithm.default()
        keygen = EnvCmd(
            "KEYGEN", f"-q -a {alg.number} -b {alg.bits} -K {KEYDIR} -L 3600"
        )
        key_name = keygen(f"{params} {self.name}", cwd=self.ns.name).out.strip()
        return Key(key_name, keydir=keydir)

    def add_keys(self, ksk=True, zsk=True) -> None:
        """Generate KSK and/or ZSK and append both to self.keys."""
        if ksk:
            self.keys.append(self.make_key("-f KSK"))
        if zsk:
            self.keys.append(self.make_key())

    def copy_dssets(self) -> None:
        """Copy dsset-* files from each delegation's ns dir into self.ns dir."""
        for zone in self.delegations:
            try:
                shutil.copy(f"{zone.ns.name}/dsset-{zone.name}.", self.ns.name)
            except FileNotFoundError:
                debug(f"{zone.name}: delegation is insecure (no dsset found)")
            else:
                debug(f"{zone.name}: delegation is secure")

    def render(self, template: str | None = None) -> None:
        """Render the unsigned zone file from a jinja2 template."""
        debug(f"{self.name}: rendering zone file")
        templates = TemplateEngine(".")
        output = Path(self.ns.name) / self.filepath_unsigned
        output.parent.mkdir(exist_ok=True)

        if template is None:
            local = f"{output}.j2.manual"
            common = "_common/zones/template.db.j2.manual"
            template = local if Path(local).is_file() else common

        data = {
            "zone": self,
            "delegations": self.delegations,
        }
        templates.render(str(output), data, template=template)

    def sign(self, params: str = "") -> None:
        """Sign the rendered zone file. Requires self.signed == True."""
        assert self.signed, f"{self.name}: zone is not configured for signing"
        debug(f"{self.name}: signing zone")
        signer = EnvCmd("SIGNER", f"-S -g -K {KEYDIR} {params}")
        signer(
            f"-P -x -O full -o {self.name}"
            f" -f {self.filepath_signed} {self.filepath_unsigned}",
            cwd=self.ns.name,
        )

    def configure(self, template: str | None = None) -> None:
        """Perform full zone setup."""
        self.copy_dssets()
        if self.signed:
            self.add_keys()
        self.render(template)
        if self.signed:
            self.sign()

    def trust_anchor(
        self, type: str = "static-ds"  # pylint: disable=redefined-builtin
    ) -> TrustAnchor:
        assert self.keys, "no zone keys configured"
        return self.keys[0].into_ta(type)


def configure_root(
    delegations: list[Zone],
    ns: Nameserver = NS1,
    signed: bool = True,
) -> Zone:
    zone = Zone(".", ns, signed=signed)
    zone.delegations = delegations
    zone.configure(template="_common/zones/root.db.j2.manual")
    return zone
