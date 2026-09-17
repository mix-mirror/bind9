<!--
Copyright (C) Internet Systems Consortium, Inc. ("ISC")

SPDX-License-Identifier: MPL-2.0

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0.  If a copy of the MPL was not distributed with this
file, you can obtain one at https://mozilla.org/MPL/2.0/.

See the COPYRIGHT file distributed with this work for additional
information regarding copyright ownership.
-->

SBOM Generation and Signing for the BIND 9 Container Image
==========================================================

Status: design + proof of concept (2026-09). This is a living document;
the "Open questions" section lists what is still undecided.

Scope
-----

This document covers the official BIND 9 container image published as
`docker.io/internetsystemsconsortium/bind9`, built from the
[`isc-projects/bind9-docker`](https://gitlab.isc.org/isc-projects/bind9-docker)
repository. It decides:

- which tool generates the Software Bill of Materials (SBOM) and in
  which format,
- how the SBOM is attached to the image,
- how the image is signed, with which trust model, and what ISC
  promises to consumers ("signing policy"),
- how this relates to the signing ISC already does for source tarballs
  and RPMs,
- how consumers verify the result.

The proof of concept (PoC) lives temporarily in this repository's
`.gitlab-ci.yml` (jobs `docker-image`, `docker-image:sign`,
`docker-image:sign-keyless`, `docker-image:cloudsmith`), because this
repository already produces
the source tarball, has the runners, and has a job that builds the
image from that tarball. The jobs are written so that they can be
lifted into `bind9-docker` unchanged once that repository gets a
pipeline of its own.

Out of scope for now: the CI-only images in
[`isc-projects/images`](https://gitlab.isc.org/isc-projects/images),
multi-architecture images, SLSA level 3 build isolation, and shipping
Kubernetes admission policies (examples are given, but ISC does not
maintain them).

Current state
-------------

- The image is built by Docker Hub's automated build from the GitHub
  mirror of `bind9-docker`, for `linux/amd64` only. `bind9-docker`
  contains a `Dockerfile` and `named.conf`; it has no CI pipeline.
- The only integrity mechanism is the SHA-256 of the release tarball
  baked into the Dockerfile (`ARG BIND9_CHECKSUM`). The manual release
  job `update-docker-image` in this repository bumps
  `BIND9_VERSION`/`BIND9_CHECKSUM` and pushes to `bind9-docker`, which
  triggers the Docker Hub build.
- The image carries no signature and no SBOM.
- Source tarballs are signed with a GPG detached signature (job
  `sign`). The signing runs on a dedicated `signer` host: the CI job
  only writes a script and waits until a human executes it over SSH,
  so the key never touches GitLab.
- RPMs are not signed by this project at all: the `rpms-cloudsmith-*`
  and `rpms-copr` jobs hand off to `bind9-qa/releng/update_rpms.py`,
  and Cloudsmith and Copr sign the packages with their own repository
  keys.

Goals and non-goals
-------------------

Goals:

1. Every published image digest has an SBOM describing exactly that
   digest.
2. Every published image digest carries a signature that anyone can
   verify offline with public material ISC publishes.
3. The SBOM is bound to the image by the same signature mechanism, so a
   consumer can trust the SBOM without trusting the registry.
4. Nothing leaks embargoed information (security releases are prepared
   in the `isc-private` namespace).
5. The tooling is pinned and checksum-verified; a compromised upstream
   release must not silently enter the pipeline.

Non-goals (for this iteration): SLSA L3, multi-arch, signing the CI
images, signing Helm charts, vulnerability scanning of the SBOM (that
is a consumer of the SBOM, not part of producing it).

SBOM generator
--------------

**Decision: [syft](https://github.com/anchore/syft), pinned by version
and SHA-256.**

| Tool | Scope | Formats | Notes |
|------|-------|---------|-------|
| syft (Anchore) | container images, filesystems, directories | CycloneDX 1.x, SPDX 2.x/3.x, syft-json, several more | Single-purpose SBOM generator, best-in-class ecosystem coverage (apk, dpkg, rpm, Go/Rust binaries, ...). One scan can emit every format. The de-facto default in 2026. |
| Trivy (Aqua) | images, filesystems, IaC, secrets, vulnerabilities | CycloneDX, SPDX | Multi-tool scanner; SBOM is a side feature. Its ecosystem was compromised in March 2026 ([GHSA-69fq-xp46-6x23](https://github.com/advisories/GHSA-69fq-xp46-6x23): malicious `v0.69.4`-`v0.69.6` releases and force-pushed `trivy-action` tags harvested CI secrets). Not disqualifying by itself, but it is the argument for pinning by checksum rather than by tag, for any tool. |
| cdxgen (OWASP) | application source trees, build systems | CycloneDX only | Strongest for language ecosystems from source; weaker for OS packages in an image. Better fit for a source-tarball SBOM later. |
| BuildKit built-in (`docker buildx build --sbom=true --provenance=mode=max`) | the build itself | SPDX 2.x as in-toto attestation manifests inside the image index | Uses syft under the hood. Zero extra tooling and Docker Hub renders it, but it needs the `docker-container` driver, it is not signed with cosign, and consumers need buildx-aware tooling to read it. Candidate for a later iteration together with multi-arch. |
| apk2sbom | Alpine images only | CycloneDX, SPDX | Reads the apk database directly. Too narrow; the image also contains BIND itself, which is not an apk package. |
| GitLab Container Scanning template | images | CycloneDX (`gl-sbom-report.cdx.json`) | Trivy-based, produced as a job report for GitLab's dependency list. Useful for the GitLab UI, but it does not produce a signable artifact for consumers. |

Rationale: the image is Alpine plus a BIND 9 build from a tarball.
syft catalogues the apk packages, and `--source-name`/`--source-version`
let the SBOM name the top-level component `bind9 <version>`. A single
syft invocation emits every format we want, so the format choice does
not constrain the tool.

Supply-chain hygiene for the generator itself: the PoC downloads the
syft and cosign release binaries by exact version from GitHub releases
and verifies them against SHA-256 checksums pinned in
`.gitlab-ci.yml`. Bumping a tool is a reviewed diff. Distribution
packages (`apk add`) lag upstream and syft is not packaged at all; the
official `gcr.io/projectsigstore/cosign` image is distroless and
useless as a GitLab job image.

SBOM format
-----------

**Decision: generate three documents from one syft scan:**

| Output | Purpose |
|--------|---------|
| `cyclonedx-json@1.6` | Primary. Attested to the image (`cosign attest --type cyclonedx`). |
| `spdx-json@2.3` | Secondary. Attested to the image (`cosign attest --type spdxjson`). |
| `syft-json` | Lossless native format, kept as a job artifact so any other format can be re-derived without rescanning. |

Rationale:

- CycloneDX 1.6 has the most mature CI emitters and consumers in 2026
  (vulnerability tooling, Kyverno's `sbom/cyclone-dx` referrer type,
  GitLab's `reports: cyclonedx` ingestion). It is the format
  security-minded consumers ask for.
- SPDX is what license-compliance consumers ask for, and the regulatory
  text (BSI TR-03183-2, used for the EU Cyber Resilience Act) accepts
  either CycloneDX 1.6+ or SPDX 3.0.1+. Producing both is cheap and
  avoids arguing with either camp.
- SPDX 3.0.1 is emitted by syft (since 1.46) but cosign has no
  predicate type for it yet, so it would have to be attested as
  `--type custom`. Switch when cosign and the consumers catch up.

Attaching the SBOM to the image
-------------------------------

**Decision: `cosign attest`, never `cosign attach sbom`.**

`cosign attach sbom` uploads the SBOM as an unsigned blob under a
`sha256-<digest>.sbom` tag. It has been deprecated since February 2024
because nothing proves who produced that blob.

`cosign attest --type cyclonedx --predicate sbom.cdx.json <image@digest>`
wraps the SBOM in an [in-toto](https://in-toto.io/) statement whose
subject is the image digest, signs it as a DSSE envelope, and stores it
next to the image. `cosign verify-attestation --type cyclonedx`
verifies signature, subject and predicate type in one step, and the
same verb verifies any other attestation (SLSA provenance, VEX, ...)
we add later. Kyverno, sigstore policy-controller and Chainguard's
tooling all consume this form.

`syft attest` exists and does the same thing with cosign's libraries,
but running syft and cosign as two explicit steps keeps the SBOM as a
plain artifact (for the GitLab dependency list and for humans) and
keeps the signing step free of any tool that is not cosign.

Signing method
--------------

### Options

| Option | Key custody | Who can verify | Public transparency log | Human in the loop | Reuses existing GPG key |
|--------|-------------|----------------|-------------------------|-------------------|-------------------------|
| **Sigstore keyless** (GitLab OIDC → Fulcio short-lived cert, Rekor) | none; identity is the CI job | cosign, Kyverno, policy-controller, podman/CRI-O (`fulcio` + `rekorPublicKeyPath`) | yes, mandatory (Rekor) | no | no |
| **cosign key pair in CI variables** | encrypted key + password as project variables | cosign, Kyverno, policy-controller, podman/CRI-O (`keyPath`) | optional (`--tlog-upload`) | no | no (GPG keys cannot be imported, [cosign#3141](https://github.com/sigstore/cosign/issues/3141)) |
| **cosign key in a KMS / OpenBao / Vault transit** (`--key hashivault://...`, job authenticates with a GitLab ID token) | HSM/KMS; key never leaves it | same as key pair | optional | no | no |
| **Hardware token on the `signer` host** via the existing `.signer-ssh-job` pattern (`--key pkcs11:` / `--sk`) | hardware, offline host | same as key pair | optional | yes, like tarballs today | possible only as a new slot on the same token; not the same key |
| **containers/image "simple signing"** (`podman push --sign-by <gpg-fingerprint>`, `skopeo`) | existing GPG key | podman/CRI-O only, via `policy.json` `signedBy`; signatures live on a separate "lookaside" HTTP server ISC would have to run | no | yes (same as tarballs) | **yes** |
| **Notation / Notary v2** | X.509 certificate, own PKI or cloud KMS | notation, Kyverno (Notary attestor), Azure/AWS admission | no (optional TSA) | no | no |
| Docker Content Trust (Notary v1) | | | | | retired by Docker; not an option |

### Decision

- **Target: Sigstore keyless.** No long-lived secret to protect or
  rotate, the signature encodes *which pipeline of which project on
  which ref* produced the image, and every signature is publicly
  auditable in Rekor. Verification needs no key distribution: the
  consumer pins an issuer and an identity string.
- **Interim (PoC): a cosign key pair held in GitLab CI variables.** It
  is the only option that works on `gitlab.isc.org` today (see the
  next section) and it exercises exactly the same registry, format and
  verification path as keyless, so nothing is thrown away when the
  switch happens. The key is password-encrypted at rest; the password is
  a masked variable; the sign job is separate from the build job so the
  key is never exposed to the job that runs docker-in-docker and pulls a
  Dockerfile from another repository.
- **Rejected: reusing the tarball/RPM GPG key via simple signing.** It
  is attractive because it is the key ISC already publishes, but only
  podman/CRI-O consume that format, Docker Hub cannot serve the lookaside
  signatures, and none of cosign, Kyverno or GitLab can verify them.
  ISC would run a signature web server for the benefit of one runtime.
  The RPMs are, in any case, signed by Cloudsmith/Copr keys rather than
  by this key, so there is no "one key for everything" to preserve.
- **Rejected: Notation.** Its trust model (X.509 chains, trust
  policies, enterprise PKI) suits organisations with an internal CA and
  a cloud-provider admission stack. ISC's consumers are the open-source
  public; cosign is what they and their tools expect. Nothing prevents
  adding a Notation signature later if a downstream requires it.
- **Later, if a key must persist** (for example as a fallback for
  embargoed builds): move the key pair into a KMS/OpenBao transit key or
  onto the hardware token on the `signer` host, rather than keeping PEM
  in CI variables.

### Keyless prerequisites on gitlab.isc.org

1. GitLab issues the OIDC token when the job declares

   ```yaml
   id_tokens:
     SIGSTORE_ID_TOKEN:
       aud: sigstore
   ```

   and cosign picks it up automatically (`COSIGN_YES=true` suppresses
   the interactive prompt; cosign >= 2.0.1). The `id_tokens` block must
   be in the project's own `.gitlab-ci.yml`; it does not work from
   child pipelines or from CI files included from another project.
2. The public Sigstore instance (Fulcio) only issues certificates for
   OIDC issuers listed in
   [`sigstore/fulcio` `config/identity/config.yaml`](https://github.com/sigstore/fulcio/blob/main/config/identity/config.yaml).
   Today that is `gitlab.com`, `dev.gitlab.org`, `ops.gitlab.net` and
   `gitlab.archlinux.org`. **`https://gitlab.isc.org` must be added by
   an upstream pull request** (type `gitlab`, client ID `sigstore`), the
   way Arch Linux did. The instance's OIDC discovery endpoint
   (`/.well-known/openid-configuration` and JWKS) must be publicly
   reachable. Until then, keyless signing from gitlab.isc.org fails at
   Fulcio with an "issuer not trusted" error; the PoC's
   `docker-image:sign-keyless` job is deliberately kept as a readiness
   probe for that moment.
3. The alternative to the public instance is a private Sigstore stack
   (Fulcio + Rekor + TUF root, via `sigstore/scaffolding`). That buys
   control at the cost of running a CA and a transparency log, and
   consumers must be given ISC's TUF root instead of using the public
   defaults. Not recommended unless the Fulcio PR is refused.
4. The certificate identity to verify against will be
   `https://gitlab.isc.org/isc-projects/bind9-docker//.gitlab-ci.yml@refs/heads/v9.21`
   (issuer `https://gitlab.isc.org`); the double slash is part of the
   format. For the PoC in this repository it is
   `https://gitlab.isc.org/isc-projects/bind9//.gitlab-ci.yml@refs/...`.

### Embargo caveat

Rekor is public and a Fulcio certificate carries the project path, the
ref and the pipeline ID. Signing an image in the `isc-private` tag
pipeline would therefore publish the existence of a security release
before the embargo lifts. Consequences:

- Sign at **publication** time, from the public `bind9-docker` project,
  not at tag time. This is already how the release flow works: the
  image is built only after `update-docker-image` pushes the version
  bump.
- Anything that must be signed while embargoed uses the key pair with
  `--tlog-upload=false` (and consumers verify with
  `--insecure-ignore-tlog`), or is simply not signed until public.
- Even key-based `cosign sign` uploads to Rekor by default; the entry
  contains the digest and the public key, not the image name. Harmless
  for public images, but keep `--tlog-upload=false` in mind for private
  registries.

Signing and verification policy
-------------------------------

What ISC commits to once this is in production:

1. **Every published image digest is signed by digest**, never by tag.
   Tags move; the signature is bound to the manifest digest, and
   `cosign verify image:tag` resolves the tag first and then verifies
   the digest, so tag-based use still works for consumers.
2. **Every published image digest carries two SBOM attestations**
   (CycloneDX 1.6 and SPDX 2.3) produced from the pushed image, so the
   SBOM subject is the registry digest.
3. **Signatures and attestations are stored in the same repository as
   the image**, so mirroring with `cosign copy` or `crane copy
   --all-tags` carries them along.
4. **Verification material is published** at a stable URL: the interim
   public key under `https://downloads.isc.org/isc/bind9/keys/` and in
   the `bind9-docker` repository; after the switch to keyless, the
   issuer and identity strings in the same places and in the ARM.
5. **Key rotation and revocation** (interim key pair): generate a new
   pair, re-sign the currently supported tags, publish the new public
   key next to the old one with validity dates, announce on
   `bind-announce`. A compromised key is removed from the download
   location and the affected digests are re-signed with the new key.
   With keyless there is no key to rotate; a compromised pipeline is
   handled by revoking the GitLab credentials and, if needed, by the
   Rekor audit trail identifying exactly which signatures it produced.
6. **Tooling is pinned.** Versions and checksums of syft and cosign are
   in `.gitlab-ci.yml` and change only through reviewed merge requests.

### Consumer verification

Interim key pair:

```sh
cosign verify \
    --key https://downloads.isc.org/isc/bind9/keys/cosign-bind9.pub \
    docker.io/internetsystemsconsortium/bind9:9.21

cosign verify-attestation \
    --key https://downloads.isc.org/isc/bind9/keys/cosign-bind9.pub \
    --type cyclonedx \
    docker.io/internetsystemsconsortium/bind9@sha256:<digest> \
    | jq -r .payload | base64 -d | jq .predicate > bind9.cdx.json
```

Keyless (after the Fulcio registration):

```sh
cosign verify \
    --certificate-oidc-issuer https://gitlab.isc.org \
    --certificate-identity 'https://gitlab.isc.org/isc-projects/bind9-docker//.gitlab-ci.yml@refs/heads/v9.21' \
    docker.io/internetsystemsconsortium/bind9:9.21
```

Kubernetes admission with Kyverno (illustrative, keyless form):

```yaml
apiVersion: policies.kyverno.io/v1
kind: ImageValidatingPolicy
metadata:
  name: bind9-signed-with-sbom
spec:
  matchImageReferences:
    - glob: "docker.io/internetsystemsconsortium/bind9:*"
  attestors:
    - name: isc
      cosign:
        keyless:
          identities:
            - issuer: https://gitlab.isc.org
              subject: https://gitlab.isc.org/isc-projects/bind9-docker//.gitlab-ci.yml@refs/heads/v9.21
        ctlog:
          url: https://rekor.sigstore.dev
  attestations:
    - name: sbom
      intoto:
        type: https://cyclonedx.org/bom
  validations:
    - expression: >-
        images.containers.map(image,
          verifyImageSignatures(image, [attestors.isc])).all(e, e > 0)
      message: image is not signed by ISC
    - expression: >-
        images.containers.map(image,
          verifyAttestationSignatures(image, attestations.sbom, [attestors.isc])).all(e, e > 0)
      message: image has no ISC-signed CycloneDX SBOM
```

podman / CRI-O (`/etc/containers/policy.json`, interim key):

```json
{
  "default": [{"type": "insecureAcceptAnything"}],
  "transports": {
    "docker": {
      "docker.io/internetsystemsconsortium/bind9": [
        {
          "type": "sigstoreSigned",
          "keyPath": "/etc/pki/containers/cosign-bind9.pub",
          "signedIdentity": {"type": "matchRepository"}
        }
      ]
    }
  }
}
```

The keyless variant replaces `keyPath` with `fulcio: {caPath, oidcIssuer,
subjectEmail|subjectRegexp}` and `rekorPublicKeyPath`. Note that
containers/image reads the legacy `sha256-<digest>.sig` tag layout; see
the next section.

Image format and build tool
---------------------------

**Decision: publish OCI-format images; move the build from
docker-in-docker to buildah when the PoC moves to `bind9-docker`.**

### OCI, not Docker, media types

Two manifest formats exist for the same image content. The Docker format
(`application/vnd.docker.distribution.manifest.v2+json`, Docker layer
media types) is Docker Inc.'s original registry format. The OCI image
format (`application/vnd.oci.image.manifest.v1+json`, OCI index and
layer media types) is the open standard published by the Open Container
Initiative under the Linux Foundation, implemented by every current
runtime and registry (Docker, containerd, CRI-O, podman, Docker Hub,
GitLab, Cloudsmith, Harbor, ECR, ...). The OCI specifications are also
where everything this document relies on is defined: the `subject`
field and `artifactType` of the image spec 1.1, and the referrers API of
the distribution spec 1.1.

The PoC currently produces Docker-format manifests: `docker build` with
the default `docker` driver exports through the docker exporter, whose
`oci-mediatypes` option defaults to `false`, and `docker push` sends the
result as is. cosign and syft do not care (cosign signs the digest and
stores its own OCI manifests next to it), so nothing in the PoC breaks,
but:

- referrers are specified for OCI manifests; a Docker-format `subject`
  works on the registries we care about by tolerance, not by spec;
- BuildKit's built-in provenance and SBOM attestations, the candidate
  for a later iteration, exist only as OCI image index output;
- multi-arch images are OCI indexes anyway, so starting with OCI avoids
  changing the shape of what gets signed twice;
- an open format is the right thing to publish from an open-source
  project, and the Docker format is the legacy path.

With docker-in-docker this means building with a `docker-container`
builder (`docker buildx create --use`) and pushing with `--output
type=image,oci-mediatypes=true,push=true`, taking the digest from
`--metadata-file` rather than from the local image store, and pulling
the pushed digest back for the `named -V` smoke test. The
`docker-container` driver also adds a provenance attestation by default,
which turns even a single-platform push into an index of two manifests;
pass `--provenance=false` until the BuildKit attestations are adopted
deliberately, so that the signing jobs keep signing one plain manifest.
With buildah, OCI is simply the default.

### buildah instead of docker-in-docker

The `docker-image` job runs a privileged `docker:dind` service to get a
daemon to build with. That is the pattern the CI-images project uses and
it works, but it is the weakest link in a supply-chain pipeline: a
privileged sidecar, a daemon socket reachable from the job, and a
floating `docker:dind` image that is not itself verified.

[buildah](https://buildah.io/) (CNCF, part of the podman ecosystem)
builds the same Dockerfile without a daemon and without privileges:

- `buildah build --format oci` is the default; `--format docker` exists
  for compatibility.
- `--build-context tarball=build/meson-dist` is supported, so the
  `bind9-docker` Dockerfile's `tarball` stage works unchanged.
- Rootless operation in a plain (non-privileged) GitLab job needs
  `--isolation chroot` and the `vfs` storage driver (fuse-overlayfs is
  not available without `/dev/fuse`); GitLab documents this setup with
  the `quay.io/buildah/stable` image. `vfs` is slower for large builds;
  a runner with `/dev/fuse` mapped in lets `fuse-overlayfs` be used.
- `buildah build --sbom syft-cyclonedx --sbom-output sbom.cdx.json`
  runs syft over the build result itself (scanner image
  `ghcr.io/anchore/syft`, pinnable with `--sbom-scanner-image`), which
  makes the separate scan step optional. Whether to use it or keep the
  explicit syft invocation is a matter of which one is easier to pin;
  the explicit invocation currently is.
- `buildah push` pushes to any registry and honours the same
  `~/.docker/config.json` or `--authfile` credentials, so the digest for
  signing comes from `buildah push --digestfile`.
- `--platform` and `--manifest` produce a multi-arch OCI index later.

kaniko, the other daemonless option GitLab used to document, was
archived by Google in June 2025 and is not an option. Rootless BuildKit
(`moby/buildkit:rootless`) is a viable alternative to buildah with the
same OCI output and the built-in attestations; buildah is preferred here
because it needs no daemon at all, is OCI-first, and comes from the same
ecosystem as podman and skopeo, which the verification examples in this
document already use.

The switch is deferred until the jobs move to `bind9-docker`, because the
PoC deliberately reuses Michal's existing `docker-image` job and the
`docker` runner tag, and because the runners' support for rootless
buildah (`/dev/fuse`, user namespaces) has to be checked first (open
question).

Registry storage
----------------

cosign 3.x stores signatures and attestations as
[Sigstore bundles](https://github.com/sigstore/cosign/blob/main/specs/BUNDLE_SPEC.md)
(`application/vnd.dev.sigstore.bundle.v0.3+json`) attached to the image
as OCI 1.1 referrers. On a registry without the referrers API it falls
back to the referrers tag scheme (an index tagged `sha256-<digest>`).
`--new-bundle-format=false` produces the pre-3.0 layout instead:
separate `sha256-<digest>.sig` and `sha256-<digest>.att` tags, each a
small image manifest.

What that means for ISC's registries:

- **Docker Hub** implements OCI distribution 1.0.1 and has no referrers
  API, so bundles land in the tag fallback. The legacy layout is the
  one every consumer (cosign 2.x, podman/CRI-O, Kyverno, Harbor
  replication) understands today.
- **gitlab.isc.org's registry** needs the container registry metadata
  database to display signatures and, per GitLab's docs, "does not
  fully implement the OCI 1.1 Referrers API".
- **Decision for now:** let the PoC run with cosign's defaults, look at
  `cosign tree` output, and record here which layout actually landed.
  If bundles are rejected or invisible to consumers, publish with
  `--new-bundle-format=false` (the PoC exposes this as the
  `COSIGN_EXTRA_ARGS` variable) until the consumer side has caught up.
  Both layouts verify with cosign 3.x.

PoC result (fill in after the first successful pipeline): _layout
observed on registry.gitlab.isc.org: TBD_.

Cloudsmith
----------

ISC already distributes container images through Cloudsmith: the public
repository `isc/docker` holds the Kea images
(`docker.cloudsmith.io/isc/docker/kea-dhcp4:<version>` and friends), and
BIND 9 subscription packages are served from private Cloudsmith
repositories. Public BIND 9 RPMs go to Copr, not Cloudsmith. The BIND 9
container image is not on Cloudsmith today. Everything below was checked
against the public `isc/docker` repository and its API on 2026-09-17.

### What Cloudsmith gives us by just pushing

| Feature | What it is | Verified state on `isc/docker` |
|---------|------------|-------------------------------|
| OCI 1.1 registry with referrers API | Signatures, attestations and SBOMs pushed with cosign are stored as proper referrers of the image, discoverable through `/v2/<repo>/<image>/referrers/<digest>`. | Working: the endpoint answers with an (empty) OCI index. Cloudsmith is the best-behaved of the three registries in this document; Docker Hub and the GitLab registry fall back to tags. |
| Repository GPG signature | Every Docker package gets a detached GPG signature over its manifest JSON, stored as `gpg.<id>.asc` next to the manifest on `dl.cloudsmith.io` and linked from the package API (`signature_url`). The key is generated by Cloudsmith per repository: `Cloudsmith Package (isc/docker) <support@cloudsmith.io>`, RSA 3072, fingerprint `DCFA ED12 8C1E F977 926A 4E02 BD92 4E2B DFAB FCAB`. The same model signs the Kea and subscription RPM/DEB repositories. A customer-provided GPG key can replace the generated one. | Present on all Kea images. |
| Automatic cosign signature | Per-repository toggle. On every push (and every upstream proxy pull) Cloudsmith signs the image with a repository ECDSA key it generates and holds. Nothing is logged to Rekor; consumers verify with `cosign verify --private-infrastructure=true --key <repo-ecdsa.pub> <image>`. The docs call this early access and do not say whether the key can be customer-provided, whether an index or each platform manifest is signed, or how it coexists with signatures pushed by the publisher. | Off. No Kea image carries any cosign signature. |
| SBOM generation and security scanning | During package synchronisation Cloudsmith generates a CycloneDX SBOM and scans it; the SBOM is a file (`tag: sbom-cyclonedx`) in the package's `files` list, downloadable from the REST API. It is not attached to the image as a referrer and not signed. | Not available on ISC's plan: the Kea packages show `Security Scanning Skipped`, have no SBOM file, and the vulnerability endpoint answers "an upgrade to the Package (Ultra) plan is required". |
| OIDC authentication from GitLab CI | GitLab is a supported OIDC provider. A job's ID token (`aud: https://api.cloudsmith.io/openid/isc/`) is exchanged at `https://api.cloudsmith.io/openid/isc/` (JSON body `oidc_token`, `service_slug`) for a token valid for two hours, usable as `X-Api-Key` and as the password for `docker login docker.cloudsmith.io` with the service account name as user. | Needs a one-time provider and service-account setup in the Cloudsmith workspace. |
| Enterprise Policy Manager | OPA/Rego policies acting on package metadata, vulnerabilities and licences, able to quarantine or block downloads. Signature-related inputs are not documented in the public recipes. | Not relevant for a public repository. |
| Upstream proxying of Docker Hub | A Cloudsmith repository can pull through Docker Hub and cache. | If ISC proxied Docker Hub, the proxied image would get Cloudsmith's own signature, but ISC's Docker Hub signatures (stored under fallback tags) would not necessarily follow. Publish directly instead. |

In short: by pushing to `isc/docker`, Cloudsmith users get the same
repository-level GPG signature they already trust for Kea and for RPM/DEB
repositories, at no cost, and can additionally get a registry-level
cosign signature by flipping a switch. That is worth having.

### What that does not cover, and why the pipeline still does more

- **A registry signature is not a producer signature.** Cloudsmith's key
  (GPG or ECDSA) proves that a digest passed through the `isc/docker`
  repository; any account with push rights gets the same signature. It
  does not prove that ISC's pipeline built the image from a given tag.
  The supply-chain question consumers ask is the latter, and only a key
  ISC controls, or a keyless identity of ISC's pipeline, answers it.
- **Docker Hub is the primary channel** (millions of pulls) and every
  Cloudsmith feature stops at Cloudsmith's edge. The signature and SBOM
  have to travel with the image wherever it is pulled from.
- **The SBOM has to be ours, and attached.** Cloudsmith's SBOM exists
  only on a plan ISC does not have, is downloadable only from
  Cloudsmith's API, is unsigned, and is not bound to the image digest.
  Regulators (BSI TR-03183-2 / CRA) expect the manufacturer to produce
  the SBOM. syft in the build pipeline yields one SBOM per digest,
  identical on every registry, attested and bound to the digest.
- **Plan and vendor independence.** Producing signature and SBOM in the
  pipeline keeps the guarantees the same if the registry, or the plan,
  changes.

So the design stays as described in the previous sections, and Cloudsmith
becomes a second publication target that happens to store the result
better than the other two registries.

### How: publish to Cloudsmith from the pipeline

The PoC job `docker-image:cloudsmith` does this (manual, never on tag
pipelines):

1. Obtains a GitLab ID token with
   `aud: https://api.cloudsmith.io/openid/isc/` and exchanges it at
   `https://api.cloudsmith.io/openid/isc/` for a Cloudsmith token, using
   the service account named by `CLOUDSMITH_SERVICE_SLUG`. No Cloudsmith
   API key is stored in CI.
2. Copies the already built and pushed image by digest from the GitLab
   registry to `docker.cloudsmith.io/isc/${CLOUDSMITH_REPOSITORY}/bind9`
   with `crane copy` (pinned and checksum-verified like syft and cosign).
   The manifest is copied byte for byte, so the digest is the same.
3. Signs the Cloudsmith copy by its own digest and attests both SBOMs to
   it with the same cosign key, then verifies with the public key and
   prints `cosign tree`, which also shows Cloudsmith's own signature if
   automatic signing is enabled on the repository.

Required one-time setup, outside this repository:

- In the Cloudsmith workspace: an OIDC provider for issuer
  `https://gitlab.isc.org` with a claim restriction (at least `aud`;
  preferably `project_path` and `ref` as well), a service account with
  push rights on the target repository, and a PoC repository (do not
  push merge-request builds into the production `isc/docker`).
- In the GitLab project: CI variables `CLOUDSMITH_REPOSITORY` (the PoC
  repository slug) and `CLOUDSMITH_SERVICE_SLUG`, plus the `COSIGN_*`
  variables from the section on CI variables.

For production the same job moves into `bind9-docker` and publishes to
`isc/docker`, next to the Kea images. Enabling Cloudsmith's automatic
cosign signature on that repository is a separate, cheap decision that
does not conflict with this design, provided a test push confirms that
ISC's own signature and attestations survive next to it (open question).

Multi-architecture images
-------------------------

Not part of this iteration. When `bind9-docker` moves to
`docker buildx build --platform linux/amd64,linux/arm64`, the published
reference becomes an image index:

- sign the index with `cosign sign --recursive`, which also signs each
  platform manifest;
- generate one SBOM per platform manifest (`syft registry:<image@platform-digest>`)
  and attest each, because package sets differ per architecture;
- BuildKit's `--sbom=true --provenance=mode=max` becomes attractive at
  that point since it does the per-platform work natively; its output
  can additionally be attested with cosign.

Provenance (SLSA)
-----------------

Also deferred, but the pieces are known:

- GitLab Runner emits an unsigned SLSA v1 provenance statement
  (`artifacts-metadata.json`) when `RUNNER_GENERATE_ARTIFACTS_METADATA`
  is `true`. That is SLSA level 1 provenance.
- BuildKit `--provenance=mode=max` emits SLSA provenance for the image
  build itself.
- Either can be attested with `cosign attest --type slsaprovenance1`,
  which makes it verifiable and gets to level 2. Level 3 needs an
  isolated, non-falsifiable build platform and is a separate project.
- The existing `reprotest` job (reproducible tarball builds) is a
  useful complement: a consumer can rebuild the tarball and compare it
  against the digest recorded in the provenance.

Rollout
-------

1. **This merge request:** design document and PoC jobs in this
   repository. Jobs never run on tag pipelines and never block a
   pipeline (manual on merge requests, non-blocking on schedules).
   Requires three project CI variables (see below).
2. **Fulcio registration:** pull request against `sigstore/fulcio`
   adding `https://gitlab.isc.org`. Independent of everything else;
   start early because it depends on the Sigstore maintainers.
3. **`bind9-docker` pipeline:** add a `.gitlab-ci.yml` that builds from
   the release tarball (verifying the checksum), generates the SBOMs,
   pushes to Docker Hub with a Docker Hub access token stored as a
   protected variable and to Cloudsmith `isc/docker` via OIDC, signs and
   attests both copies. Retire the Docker Hub automated build; keep the
   GitHub mirror for visibility.
4. **Release flow:** `update-docker-image` in this repository keeps
   doing the version bump; the `bind9-docker` pipeline it triggers does
   the rest. Consider triggering it explicitly with a pipeline trigger
   so the release engineer sees the image job in the release pipeline.
5. **Publish verification material:** public key on downloads.isc.org
   and in `bind9-docker`; a verification section in the ARM / knowledge
   base; announcement.
6. **Switch to keyless** once Fulcio accepts the issuer; keep the key
   pair only if an embargoed-signing use case remains, and then move it
   out of CI variables.
7. **Follow-ups in `bind9-docker`:** build with buildah and publish
   OCI-format manifests (see "Image format and build tool"), pin
   `alpine` by digest (the SBOM otherwise drifts with every rebuild of
   `alpine:latest`), multi-arch, provenance.

### CI variables for the PoC

Created by a maintainer on a workstation and stored under *Settings →
CI/CD → Variables* of the project running the PoC. They are
unprotected during the PoC so merge-request pipelines can use them;
production keys in `bind9-docker` are protected and scoped to the
release environment.

```sh
export COSIGN_PASSWORD="$(openssl rand -base64 32)"
cosign generate-key-pair          # writes cosign.key (encrypted) and cosign.pub
cosign public-key --key cosign.key  # fingerprint for the merge request
```

| Variable | Type | Content |
|----------|------|---------|
| `COSIGN_PRIVATE_KEY` | File | `cosign.key` (password-encrypted PEM; a multi-line value cannot be masked) |
| `COSIGN_PUBLIC_KEY` | File | `cosign.pub` |
| `COSIGN_PASSWORD` | Variable, masked | the password |

Delete the local `cosign.key` after uploading it.

Open questions
--------------

- Fulcio registration: who submits the PR, and how long does acceptance
  take? Is a private Sigstore stack acceptable as plan B?
- Should the image also be published to `registry.gitlab.isc.org` or
  GHCR as a mirror? That changes where consumers verify and doubles
  the signing work (or requires `cosign copy`). Cloudsmith
  (`isc/docker`, where the Kea images live) is the obvious first
  mirror; see the Cloudsmith section.
- Cloudsmith: does enabling the repository's automatic cosign signature
  keep ISC's own signature and attestations intact, and which Cloudsmith
  plan features (SBOM generation, security scanning) does ISC's
  workspace actually have?
- Does podman/CRI-O consume cosign 3.x bundles by the time this is in
  production, or do we keep `--new-bundle-format=false`?
- Who owns `COSIGN_PASSWORD` and the key pair during the interim period?
- Do the shared runners allow rootless buildah (user namespaces,
  ideally `/dev/fuse` for `fuse-overlayfs`), or does the build need a
  dedicated runner?
- Retention: the PoC pushes `bind9:<version>-<sha>` images into the
  project registry on every run. A cleanup policy for that repository
  is needed before the schedule runs it nightly.
- Should the source tarball get an SBOM as well (cdxgen or syft on the
  tarball, attached to the release directory next to the `.asc`)? It
  is cheap and answers the same regulatory question for RPM/DEB users.

References
----------

- syft: <https://github.com/anchore/syft>, releases and checksum files
  at <https://github.com/anchore/syft/releases>
- cosign: <https://github.com/sigstore/cosign>, bundle specification
  <https://github.com/sigstore/cosign/blob/main/specs/BUNDLE_SPEC.md>,
  SBOM attachment deprecation
  <https://github.com/sigstore/cosign/issues/2755>, GPG import request
  <https://github.com/sigstore/cosign/issues/3141>
- Sigstore registry support and signing guide:
  <https://docs.sigstore.dev/cosign/signing/signing_with_containers/>,
  <https://docs.sigstore.dev/cosign/system_config/registry_support/>
- Fulcio OIDC issuers: <https://github.com/sigstore/fulcio/blob/main/docs/oidc.md>,
  <https://github.com/sigstore/fulcio/blob/main/config/identity/config.yaml>
- GitLab keyless signing: <https://docs.gitlab.com/ci/yaml/signing_examples/>,
  cosign tutorial <https://docs.gitlab.com/user/packages/container_registry/cosign_tutorial/>,
  registry OCI support <https://docs.gitlab.com/user/packages/container_registry/>,
  SLSA provenance <https://docs.gitlab.com/ci/pipeline_security/slsa/>
- BuildKit attestations: <https://docs.docker.com/build/metadata/attestations/>
- Kyverno image verification:
  <https://kyverno.io/docs/policy-types/image-validating-policy/>
- containers/image signing (podman): `containers-policy.json(5)`,
  <https://github.com/containers/podman/blob/main/docs/tutorials/image_signing.md>
- Notation: <https://notaryproject.dev/>
- Trivy supply-chain compromise (March 2026):
  <https://github.com/advisories/GHSA-69fq-xp46-6x23>
- BSI TR-03183-2 (SBOM requirements for the EU CRA):
  <https://www.bsi.bund.de/dok/TR-03183>
