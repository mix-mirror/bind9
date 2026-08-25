---
name: bind-cvss-scoring
description: >-
        Deciding whether a BIND 9 issue is CVE-eligible under the ARM's
        security assumptions and scoring it with CVSS 3.1 the way ISC does —
        base metrics only, severity not risk, assume detailed configuration
        knowledge and vulnerable configurations, with the DNS-specific
        reading of every base metric. Use whenever asked to produce, check,
        or argue a CVSS vector or score for a BIND 9 issue, to rate an issue
        Low/Medium/High/Critical, to say whether something is a security
        vulnerability at all, or when a confidential security issue or CVE
        needs a severity.
---

# Scoring BIND 9 vulnerabilities — ISC CVSS 3.1 guidelines

Sources, in order of authority:

- `doc/arm/security.inc.rst`, "Security Assumptions" — what can and
  cannot be the basis for CVE assignment. Read this first.
- `SECURITY.md` — reporting: a crash with a `REQUIRE`, `INSIST` or
  `ASSERT` failure is a potential security vulnerability; report it
  through a confidential GitLab issue (`Security_issue` template),
  never on a public list; no bug bounties, reporters are credited in
  the release notes. Scores are published under the ISC Software
  Defect and Security Vulnerability Disclosure Policy
  (https://kb.isc.org/docs/aa-00861).

## Step 1 — is it CVE-eligible at all? (ARM security assumptions)

BIND 9 assumes access to the following is limited to trusted parties.
An issue that can only be triggered through one of them is a bug, not a
vulnerability — no CVE, no security-sensitive handling, no CVSS score:

- **All files on disk** — zone files, configuration files, key files,
  and the temporary files BIND keeps next to them. Needing write access
  to any of these is effectively full DNS admin, so it is not an
  attack. Read "temporary files" as the files BIND manages in its own
  directories, not as a blanket exemption: *insecure* temporary-file
  handling — a predictable name or a world-writable location that an
  unprivileged local user can pre-create, replace or symlink — is still
  scored, as AV:L (Step 3). Misbehavior confined to the trusted files
  themselves (following a symlink in the zone directory, TOCTOU on a
  configured file) is described as a bug — see the bind-mr-description
  skill for the framing.
- **The `controls` socket with a configured key** (`rndc`).
- **`statistics-channels`** from untrusted clients.
- **Sockets used by `update-policy` type `external`**.

Also out of scope by definition:

- Problems only reachable with DNS classes other than IN (CH, HS)
  configured on views or zones.
- Resolver traffic amplification below **100 packets** for a given
  scenario — resolvers amplify by design; BIND's own limits are subject
  to change.
- Unexpected behavior caused by protocol non-conformant servers, when
  the effect is **limited to the domains those servers host**. If the
  effect escapes them (the whole resolver crashes or stalls, other
  names are poisoned), this rule no longer excludes it — it still has
  to pass the other checks here; once it does, Step 2's "assume a
  misbehaving server exists" rule applies when scoring it.
- Resource exhaustion of an authoritative server by an *authorized*
  data source (zone transfer or UPDATE) abusing the intentionally
  lenient defaults (unlimited zone size, long transfer timeouts) is a
  deployment-limits matter (`server_resource_limits`,
  `zone_transfers`), not automatically a CVE.

Note what is NOT on the trusted list: a zone **primary** is an
untrusted data source to its secondaries (normal, RPZ and catalog zones
alike). Needing a malicious primary therefore does not by itself
disqualify an otherwise eligible issue; that access is PR:H (Step 3).

## Step 2 — ground rules for scoring

- **CVSS 3.1, base metrics only.** ISC used the temporal metrics for
  about a year and dropped them in September 2022 — they did not make
  scores match the perceived severity and caused confusion. Never emit
  `E:`, `RL:` or `RC:`, and do not use CVSS 2 or 4.0.
- **Severity, not risk.** Score the intrinsic characteristics — what
  is constant over time and across the whole user base. The base score
  does NOT change because details are public, an exploit tool exists,
  badly behaved servers are out on the internet, or zone data is known.
- **Assume detailed knowledge, but no secrets.** The attacker knows the
  target's views, zones, ACLs and key *names*. They do not know any key
  secret.
- **Assume vulnerable configurations** (explicit in the 3.1 spec). If
  the exploit needs an authoritative server that misbehaves in some
  way, assume one exists and the attacker knows it. If it needs a zone
  with particular data, assume it exists and is known. If it needs a
  feature we consider "rarely used", assume it is used more than we
  think. Never discount a score with "nobody configures that".

## Step 3 — metric by metric

### Attack Vector (AV)

- **N (Network)** — almost everything against `named`, INCLUDING
  attacks that must be executed on-path (the spec's own example). An
  on-path requirement is expressed as AC:H, not as a lower AV.
- **A (Adjacent)** — only if the attack cannot be routed and must come
  from a directly connected network, e.g. it has to originate from an
  IPv6 link-local interface.
- **L (Local)** — only when local files are manipulated to accomplish
  the attack. Needing write access to configuration, zone or key files
  that are explicitly listed in the configuration is effectively full
  DNS admin, so that is not an attack at all (Step 1). What AV:L covers
  in practice is insecure temporary-file handling — a predictable name
  or a world-writable location that an unprivileged local user can
  pre-create, replace or symlink before `named` uses it — and a
  command-line tool tricked into consuming an attacker-controlled file
  that is not part of its trusted configuration.
- **P (Physical)** — never; there is no physical product.

### Attack Complexity (AC)

- **L (Low)** — the default.
- **H (High)** — the attacker must run the attack repeatedly to win a
  race condition; must be on-path for a Network attack; or must know
  sequence numbers (DNS query IDs), shared secrets (which normally also
  means PR:L or PR:H), or the configuration of other systems such as
  firewalls.

### Privileges Required (PR)

- **N (None)** — matching `allow-query` and friends is NOT a privilege,
  not even when the attack has to be carried out over TCP.
- **L (Low)** — some privileges, but not an admin. DNS examples: XFR
  privileges for a zone the target is authoritative for; credentials
  BIND can validate through GSSAPI; knowing the secret of any
  configured key (TSIG — a shared secret, so this is AC:H as well).
  What counts as XFR *privilege*:
  - bare IP-based `allow-transfer` on the public internet is not a
        security boundary by itself (unauthenticated, not
        cryptographically protected, and not something anyone should
        deploy) — it is "allow-query and friends", so PR:N;
  - XFR gated by credentials (SIG(0), GSSAPI, mutually authenticated
        DoT/DoH/DoQ) or confined to a genuinely protected network or
        channel (IPsec/VPN, internal network) is normally AC:L/PR:L — a
        client certificate or private key is a credential, not a shared
        secret;
  - XFR requiring a shared secret, such as TSIG, is AC:H/PR:L; do not
        assign AC:H merely because a credential or private key is
        required.
  Encryption alone (DoT/DoH/DoQ without client authentication) does
  not establish XFR privilege.
- **H (High)** — administrative privileges on the target system, or
  access through an administrative channel the operator has to
  configure explicitly. Examples: being primary for a zone the
  target is secondary for (normal zones, RPZ and catalog zones alike);
  holding an `rndc` key configured for the instance; having access to
  the configured statistics channel. Cross-check with Step 1: `rndc`
  key holders and statistics-channel clients are *trusted parties* per
  the ARM, so an issue that needs only those is not CVE-eligible; the
  zone-primary case is the one that gets scored at PR:H.

### User Interaction (UI)

- **N (None)** — essentially always for a daemon.
- **R (Required)** — a user or admin must act as part of the attack.
  For `named` that only means an admin having to run a specific `rndc`
  command after the attacker's move. Otherwise it is command-line tools
  such as `dig`.

### Scope (S)

- **U (Unchanged)** — only the affected component (typically `named`)
  is affected.
- **C (Changed)** — the attacker can affect things outside the affected
  component. The canonical DNS example is cache poisoning: the victims
  are the clients relying on the resolver's answers.

### Confidentiality (C)

- **N (None)**
- **L (Low)** — "ordinary" data that was not meant to be readily
  disclosed: regular zone contents (even for zones the attacker could
  not otherwise query), policy zone contents, catalog zone contents
  (unless they carry key material rather than just key names).
- **H (High)** — high-value data such as passwords or encryption keys.

### Integrity (I)

- **N (None)**
- **L (Low)** — the attacker can modify data but cannot control which
  data is modified and/or what it becomes.
- **H (High)** — the attacker controls the modification. This almost
  always implies S:C as well. Examples: zone update ACL bypass, cache
  poisoning.

### Availability (A)

- **N (None)**
- **L (Low)** — any impairment where the attacker cannot completely
  deny service to legitimate users (slowdown, CPU burn, partial loss).
- **H (High)** — the attacker can completely deny service to
  legitimate users. This explicitly includes impairment that lasts
  only as long as the attacker keeps delivering the attack, and
  eventual complete loss (the spec's example: a small memory leak that
  exhausts memory under continued exploitation). The spec still asks
  for denial that is sustained, persistent, or otherwise directly
  serious: a crash the attacker can trigger repeatedly is A:H, and a
  supervisor restarting `named` does not argue it down; a one-off,
  briefly self-recovering interruption the attacker cannot sustain may
  be A:L.

## Reference vectors

Computed with the CVSS 3.1 formula; use them as anchors, not as a
lookup table.

| Pattern | Vector | Score |
|---|---|---|
| Repeatably triggerable crash/assertion via crafted query or response, no privileges | `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` | 7.5 High |
| Same, but needs a race, on-path position, or a guessed query ID | `AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H` | 5.9 Medium |
| Same, but needs XFR privilege for a zone | `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H` | 6.5 Medium |
| Same, but needs a TSIG secret (shared secret ⇒ AC:H as well as PR:L) | `AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H` | 5.3 Medium |
| Same, but only a malicious zone primary can trigger it on a secondary | `AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H` | 4.9 Medium |
| Degradation that does not fully deny service | `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L` | 5.3 Medium |
| Cache poisoning by an attacker-run authoritative server (no spoofing needed) | `AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N` | 8.6 High |
| Cache poisoning that needs spoofed responses (query ID guessing) | `AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N` | 6.8 Medium |
| Zone contents disclosed to an unauthorized client (e.g. AXFR ACL bypass) | `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` | 5.3 Medium |
| Zone update ACL bypass | `AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N` | 8.6 High |

The crash rows assume the attacker can keep re-triggering the crash
(sustained denial). A one-off, self-recovering interruption is A:L —
see Availability above.

Qualitative ratings (CVSS 3.1): None 0.0, Low 0.1–3.9, Medium
4.0–6.9, High 7.0–8.9, Critical 9.0–10.0.

## Delivering a score

- Say first whether the issue passes Step 1. If it does not, say which
  security assumption it falls under and stop — no vector, no score,
  and use bug framing in any MR text.
- Otherwise give the full vector string
  `CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_`, the numeric base
  score, the qualitative rating, and one line of justification for
  every metric that is not the obvious default for the issue.
- Compute the number with the 3.1 formula or the FIRST calculator
  (https://www.first.org/cvss/calculator/3.1). Never estimate it, and
  never present a score without its vector.
- When a metric is genuinely arguable, show the alternative vector and
  score and say which reading the guidelines above pick and why — the
  ground rules (assume knowledge, assume vulnerable configurations,
  severity not risk) usually settle it.
