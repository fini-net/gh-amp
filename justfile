# project justfile

import? '.just/compliance.just'
import? '.just/gh-process.just'
import? '.just/pr-hook.just'
import? '.just/shellcheck.just'
import? '.just/cue-verify.just'
import? '.just/claude.just'
import? '.just/copilot.just'
import? '.just/repo-toml.just'
import? '.just/template-sync.just'

# list recipes (default works without naming it)
[group('Utility')]
list:
	just --list
	@echo "{{GREEN}}Welcome to gh-amp!{{NORMAL}}"

# install the extension locally for testing
[group('Development')]
install:
	gh extension install .

# uninstall the local extension
[group('Development')]
uninstall:
	-gh extension remove gh-amp

# run amp locally (without installing)
[group('Development')]
run *ARGS:
	./gh-amp {{ARGS}}

# run shellcheck on the extension script
[group('Quality')]
shellcheck-amp:
	shellcheck -x -s bash gh-amp

# run the function test suite (seed corpus for the fuzz targets)
[group('Quality')]
test:
	shellcheck -x -s bash .just/lib/gh-amp-test.sh .just/lib/gh-amp-fuzz.sh
	bash .just/lib/gh-amp-test.sh

# fuzz the gh-amp helpers for a time-boxed burst (opt-in; `just test`
# always runs the seed corpus, this explores deeper)
[group('Quality')]
fuzz time="30s":
	bash .just/lib/gh-amp-fuzz.sh "{{ time }}"

# dev cycle
[group('Development')]
build: shellcheck-amp uninstall && install
	# all in header

# test list
[working-directory: '../gh-observer/']
[group('Development')]
test_list:
	gh amp list

# test review
[working-directory: '../gh-observer/']
[group('Development')]
test_review:
	gh amp review

# Verify a release's cosign signature, SLSA provenance, and GitHub attestations (defaults to latest)
# Usage: just verify-release [v0.6]
# The default resolves the latest non-prerelease release (gh release view
# skips prereleases), so verifying a throwaway -rc tag requires passing it
# explicitly.
[group('Release')]
verify-release TAG=`gh release view --json tagName -q .tagName`:
	#!/usr/bin/env bash
	set -euo pipefail

	TAG="{{TAG}}"
	# Derive owner/repo from the remote so the recipe works in any clone,
	# mirroring the workflow's GITHUB_REPOSITORY-based bundle naming.
	REPO="$(gh repo view --json nameWithOwner -q .nameWithOwner)"
	BUNDLE="${REPO#*/}-${TAG}.tar.gz"
	BASE="https://github.com/${REPO}/releases/download/${TAG}"

	echo "{{BLUE}}Verifying release ${TAG} for ${REPO}...{{NORMAL}}"

	# Check required tools
	for tool in cosign slsa-verifier curl gh; do
		if ! command -v "$tool" >/dev/null 2>&1; then
			echo "{{RED}}Error: '$tool' not found. Install with: brew install $tool{{NORMAL}}"
			exit 1
		fi
	done

	# The attestation flags need a recent gh: --signer-workflow arrived
	# in 2.51.0, --source-ref in 2.68.0 (the hard floor - older gh exits
	# with an unknown-flag error). Versions before 2.102.0 also compare
	# these exact flags loosely (regex/prefix matching, case-insensitive
	# refs - see SECURITY.md), which silently weakens the pinning, so
	# warn instead of fail there. Keep these floors in sync with
	# SECURITY.md's "Verify the GitHub-native attestation" section.
	read -r GH_MAJOR GH_MINOR <<<"$(gh --version | sed -n 's/^gh version \([0-9][0-9]*\)\.\([0-9][0-9]*\)\..*/\1 \2/p')"
	if [[ -z "${GH_MAJOR:-}" ]]; then
		echo "{{RED}}Error: could not parse gh version from: $(gh --version | head -1){{NORMAL}}"
		exit 1
	fi
	if (( GH_MAJOR < 2 || (GH_MAJOR == 2 && GH_MINOR < 68) )); then
		echo "{{RED}}Error: gh 2.68.0+ required for the attestation flags (found $(gh --version | head -1)){{NORMAL}}"
		exit 1
	fi
	if (( GH_MAJOR == 2 && GH_MINOR < 102 )); then
		echo "{{YELLOW}}Warning: gh 2.102.0+ recommended - older versions compare the signer/source flags loosely (see SECURITY.md){{NORMAL}}"
	fi

	WORKDIR="$(mktemp -d)"
	trap 'rm -rf "$WORKDIR"' EXIT
	cd "$WORKDIR"

	echo "{{GREEN}}Downloading assets for ${TAG}...{{NORMAL}}"
	# Release workflow asset naming (template-repo pattern): <repo>-<tag>.tar.gz
	# bundle, .sigstore.json cosign bundle, checksums.txt, SLSA
	# multiple.intoto.jsonl. Use --fail so curl exits non-zero on 4xx/5xx
	# (e.g. 404) instead of silently saving the GitHub "Not Found" page,
	# which later makes cosign choke with "invalid character 'N' looking
	# for beginning of value".
	for ASSET in "${BUNDLE}" "${BUNDLE}.sigstore.json" "multiple.intoto.jsonl" "checksums.txt"; do
		if ! curl --fail --location --output "${ASSET}" "${BASE}/${ASSET}"; then
			echo "{{RED}}Error: failed to download ${BASE}/${ASSET} (HTTP error).{{NORMAL}}"
			echo "{{RED}}       Release ${TAG} may have no signed assets attached.{{NORMAL}}"
			echo "{{RED}}       Check: gh release view ${TAG} --repo ${REPO} --json assets -q '.assets[].name'{{NORMAL}}"
			exit 1
		fi
	done

	echo "{{GREEN}}Verifying cosign keyless signature...{{NORMAL}}"
	# Exact-match identity (not regexp): the workflow ref is always a tag
	# here, so the identity is fully known - no wildcarded dots or
	# unanchored matching.
	cosign verify-blob \
		--bundle "${BUNDLE}.sigstore.json" \
		--certificate-identity "https://github.com/${REPO}/.github/workflows/release.yml@refs/tags/${TAG}" \
		--certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
		"${BUNDLE}"

	echo "{{GREEN}}Verifying SLSA build provenance...{{NORMAL}}"
	slsa-verifier verify-artifact \
		--provenance-path multiple.intoto.jsonl \
		--source-uri "github.com/${REPO}" \
		--source-tag "${TAG}" \
		"${BUNDLE}"

	echo "{{GREEN}}Verifying GitHub-native attestations...{{NORMAL}}"
	# gh attestation verify prints nothing when not attached to a TTY but
	# still exits 0 on success - GH_FORCE_TTY keeps the output visible.
	# --signer-workflow pins the trust boundary to this release workflow,
	# --source-ref pins it to this tag, and --deny-self-hosted-runners
	# rejects attestations from runner environments outside GitHub's;
	# together they match the exact-identity cosign check above. Without
	# them, any workflow in the repo (or any ref of this one, or a
	# self-hosted run of it) could have produced the attestation.
	GH_FORCE_TTY=1 gh attestation verify "${BUNDLE}" \
		--repo "${REPO}" \
		--signer-workflow "${REPO}/.github/workflows/release.yml" \
		--source-ref "refs/tags/${TAG}" \
		--deny-self-hosted-runners
	# checksums.txt is itself an attestation subject; verifying it directly
	# means the file that pins the bundle and SBOM digests is independently
	# attested (the SLSA steps verify the same subjects separately). The
	# SBOM is a subject too but is deliberately not verified here - its
	# digest is pinned by the attested checksums.txt and the recipe never
	# downloads it.
	GH_FORCE_TTY=1 gh attestation verify checksums.txt \
		--repo "${REPO}" \
		--signer-workflow "${REPO}/.github/workflows/release.yml" \
		--source-ref "refs/tags/${TAG}" \
		--deny-self-hosted-runners

	echo "{{GREEN}}Verifying checksums.txt provenance...{{NORMAL}}"
	# checksums.txt is a SLSA subject alongside the bundle, so the
	# provenance attests it too - verifying it against the provenance
	# gives it trust beyond a same-release comparison, which only
	# catches corruption.
	slsa-verifier verify-artifact \
		--provenance-path multiple.intoto.jsonl \
		--source-uri "github.com/${REPO}" \
		--source-tag "${TAG}" \
		checksums.txt

	echo "{{GREEN}}Verifying bundle hash against checksums.txt...{{NORMAL}}"
	# With checksums.txt itself attested, regenerate the bundle hash
	# and compare against the (now trusted) file. awk matches the exact
	# filename - grep -E would treat the dots in the bundle name as
	# wildcards.
	EXPECTED="$(awk -v f="${BUNDLE}" '$2==f {print $1}' checksums.txt)"
	if [[ -z "$EXPECTED" ]]; then
		echo "{{RED}}Error: checksums.txt has no entry for ${BUNDLE}{{NORMAL}}"
		exit 1
	fi
	# sha256sum is GNU coreutils (absent on macOS); fall back to shasum -a 256
	if command -v sha256sum >/dev/null 2>&1; then
		ACTUAL="$(sha256sum "${BUNDLE}" | awk '{print $1}')"
	else
		ACTUAL="$(shasum -a 256 "${BUNDLE}" | awk '{print $1}')"
	fi
	if [[ "$EXPECTED" != "$ACTUAL" ]]; then
		echo "{{RED}}Checksum mismatch: expected $EXPECTED, got $ACTUAL{{NORMAL}}"
		exit 1
	fi

	echo "{{GREEN}}All signature and provenance checks passed for ${TAG}!{{NORMAL}}"
