# Security Policy

## Scope

`gh-amp` is a GitHub CLI extension: a bash script that runs locally with your
own `gh` credentials to list, review, approve, merge, and pull pull requests.
There is no server-side application, database, or user data. Security
considerations are limited to:

- Secrets or tokens accidentally committed to the repo
- Malicious content submitted via pull requests or issues
- Supply-chain risks in the release artifacts you download and run

Vulnerabilities in `gh` itself, `jq`, or GitHub infrastructure should be
reported to their respective upstream projects, not here.

## Automated Checks

Every pull request runs automated security scans via GitHub Actions:

- [actionlint](https://github.com/rhysd/actionlint) lints workflow syntax
  (see [`.github/workflows/actionlint.yml`](./workflows/actionlint.yml)).
- [gitleaks](https://github.com/gitleaks/gitleaks-action) scans commits for
  accidentally committed secrets or tokens
  (see [`.github/workflows/gitleaks.yml`](./workflows/gitleaks.yml)).
- [checkov](https://www.checkov.io/) and
  [zizmor](https://woodruffw.github.io/zizmor/) scan the GitHub Actions
  workflows themselves for misconfigurations and security anti-patterns.
- [OSSF Scorecard](https://github.com/ossf/scorecard) and
  dependency-review analyze supply-chain posture.

Release workflow actions are pinned to full commit SHAs and updated by
Renovate, so a reviewed PR is the only path to a new action version.

## Verifying Releases

Each tagged release (e.g. `v0.6`) ships:

- `gh-amp-<tag>.tar.gz` - the full tagged tree via `git archive` (byte-identical
  to the tag; the `.gitattributes` export-ignore list trims repo bookkeeping
  files)
- `checksums.txt` - SHA-256 digests of the bundle and SBOM
- `gh-amp-<tag>.tar.gz.sigstore.json` - a cosign keyless signature bundle
  (signature, certificate, and Rekor transparency log entry)
- `gh-amp-<tag>.tar.gz.cdx.json` - a CycloneDX SBOM of the bundle's contents
- `multiple.intoto.jsonl` - SLSA build provenance from
  [slsa-github-generator](https://github.com/slsa-framework/slsa-github-generator)

The release workflow also registers GitHub-native artifact attestations, so
`gh attestation verify` works on the bundle, the SBOM, and `checksums.txt`.

What covers what: the cosign signature covers the bundle; the SLSA provenance
covers both the bundle and `checksums.txt`; the GitHub-native attestations
cover all three. The SBOM is an unsigned inventory of the bundle's contents -
its digest is pinned by the attested `checksums.txt`. Releases published before
the signing workflow landed (before `v0.6`) have no signed assets;
`just verify-release` against them fails with a download error, which is
expected.

### Quick verify with just

```bash
# Defaults to the latest release; pass a tag to verify a specific one.
just verify-release
just verify-release v0.6
```

The recipe walks all six layers: cosign signature, SLSA provenance (bundle),
GitHub-native attestation (bundle), GitHub-native attestation (`checksums.txt`),
SLSA provenance (`checksums.txt`), and the bundle hash against the attested
`checksums.txt`.

### Verify the asset signature with cosign

```bash
# Replace v0.6 with the tag you want to verify. -fLO: fail on HTTP errors
# instead of saving a 404 page as the asset.
TAG="v0.6"
REPO="fini-net/gh-amp"
BUNDLE="gh-amp-${TAG}.tar.gz"
BASE="https://github.com/${REPO}/releases/download/${TAG}"

curl -fLO "${BASE}/${BUNDLE}"
curl -fLO "${BASE}/${BUNDLE}.sigstore.json"

cosign verify-blob \
  --bundle "${BUNDLE}.sigstore.json" \
  --certificate-identity "https://github.com/${REPO}/.github/workflows/release.yml@refs/tags/${TAG}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "${BUNDLE}"
```

### Verify SLSA build provenance

```bash
curl -fLO "${BASE}/${BUNDLE}"
curl -fLO "${BASE}/multiple.intoto.jsonl"

slsa-verifier verify-artifact \
  --provenance-path multiple.intoto.jsonl \
  --source-uri "github.com/${REPO}" \
  --source-tag "${TAG}" \
  "${BUNDLE}"
```

### Verify the GitHub-native attestation

```bash
curl -fLO "${BASE}/${BUNDLE}"
curl -fLO "${BASE}/checksums.txt"

# --signer-workflow pins the attestation to the release workflow,
# --source-ref pins it to this tag, and --deny-self-hosted-runners
# rejects attestations from self-hosted runners, so only this release
# workflow, at this tag, on GitHub's own runners can verify.
gh attestation verify "${BUNDLE}" \
  --repo "${REPO}" \
  --signer-workflow "${REPO}/.github/workflows/release.yml" \
  --source-ref "refs/tags/${TAG}" \
  --deny-self-hosted-runners

# checksums.txt is itself an attestation subject, so it verifies too.
gh attestation verify checksums.txt \
  --repo "${REPO}" \
  --signer-workflow "${REPO}/.github/workflows/release.yml" \
  --source-ref "refs/tags/${TAG}" \
  --deny-self-hosted-runners
```

The signature is produced via keyless signing using GitHub Actions OIDC
identities, so there are no long-lived signing keys to trust or rotate - you
only trust the Sigstore Fulcio certificate chain and the exact workflow
identity shown in the command above.

These flags need `gh` 2.68.0 or newer (`--signer-workflow` arrived in 2.51.0,
`--source-ref` in 2.68.0). Prefer `gh` 2.102.0 or newer: older releases
compared these exact flags loosely - `--signer-workflow` as an unescaped regex
(CVE-2026-64655, fixed in 2.97.0) and as an unchecked prefix, and
`--source-ref` case-insensitively (GHSA-wjmr-j3rp-mh2g, GHSA-4mq3-hpgx-9cx8,
fixed in 2.102.0) - so the pinning above is only as strong as the `gh` running
it. `just verify-release` enforces the same floors, so update the two together.

The SBOM is an attestation subject too but is deliberately not verified
directly here: its digest is pinned by the attested `checksums.txt`. To check
it against that file, run `shasum -a 256 --check checksums.txt` (macOS) or
`sha256sum -c checksums.txt` (Linux) next to the downloaded assets.

## Reporting a Vulnerability

Please do **not** open a public issue for security concerns. Instead, email me
privately at <chicks.net@gmail.com>.
I'll acknowledge reports within 72 hours and aim to address verified issues on
the latest `main` branch as time permits.

## Supported Versions

This is a personal hobby project with no SLA. Only the latest `main` branch
receives updates.
