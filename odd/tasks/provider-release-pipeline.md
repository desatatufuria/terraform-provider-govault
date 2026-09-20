# Provider release pipeline

## Objective

Add reproducible CI and signed GitHub release packaging so the public GoVault
provider can later be indexed and installed through the Terraform Registry.

## Problem

The provider repository is public and locally validated, but it has no CI,
release automation, or signed Registry-compatible artifacts. Creating a tag now
would not produce an installable provider release.

## Why

Terraform CLI installs public providers through Registry metadata backed by
versioned GitHub release assets. The release must preserve the provider source,
protocol, versioned binary naming, checksums, and signature expected by the
Registry.

## Authorized scope

- Implement local repository CI and release-pipeline files.
- Document release prerequisites and operator procedure.
- Validate locally without publishing anything.
- Do not push, create tags/releases, configure GitHub secrets, or register the
  provider in Terraform Registry without later explicit authorization.

## Constraints

- Provider source remains `registry.terraform.io/desatatufuria/govault`.
- Terraform minimum remains 1.10 and protocol remains 6.0.
- Release checksums must be signed with a dedicated GPG key; private key
  material must never enter the repository.
- GitHub Actions permissions must be least-privilege and third-party actions
  pinned by immutable commit SHA.
- `.codegraph/` stays untracked.
- No application behavior changes.

## Delivery and verification

- Route: delegated direct.
- Trigger evidence: implementation spans multiple non-trivial workflow,
  packaging, and documentation files; mapping and writer delegation are
  mandatory.
- Effective TDD: disabled.
- TDD source: inherited GoVault program configuration recorded by the existing
  provider ledgers (`strict_tdd: false`, `rules.apply.tdd: false`).
- Test runner: ordinary Go and release-tool checks listed per task.
- Delivery strategy: `single-pr` review-size exception, explicitly approved by
  the user after PRP-002 reached 388 authored lines. CI, release packaging, and
  their operator documentation remain one cohesive review unit; splitting the
  documentation from the workflows it describes would reduce review clarity.
- Forecast: about 360 authored changed lines, excluding generated release
  artifacts.
- Initial reviewed boundary: `aeb308e1881d742de2a0958517c84571d7b0ece5`.
- RDD mode: enabled globally; assess each committed work unit.
- RDD exception: user declined review only for CI candidate
  `eac3a9d312bbd7f1471d3594a0a2685f6e67c3b1` / target
  `sha256:273e7ac53637a444eb5d8766a84aafa2d64a45daf1f9c0d7dd1d1e2b07e86fb1`;
  ordinary policy applies to that candidate only. The user separately declined
  RDD for signed-release candidate
  `c8136ac1678a53a11b459041ab8a40d2ad8ab329` / target
  `sha256:c16bbdb289621626557bf5828dbd6260efb61cc17557157623c0affacea452b8`.

## Tasks

- [x] **PRP-001 — Continuous integration**
  - Add least-privilege CI for formatting, generation drift, vet, unit/race
    tests, build, and supported Terraform acceptance versions.
  - Ensure CI never downloads Terraform from provider tests and never exposes
    assertions or tokens.
  - Acceptance:
    - Workflow syntax is valid and actions are SHA-pinned.
    - Local Go checks pass.
  - Route: delegated writer; mapping/preparation trigger fired.
  - Evidence:
    - `.github/workflows/ci.yml` grants only `contents: read`, disables
      checkout credential persistence, and pins all six action references to
      immutable commits annotated with their release versions.
    - Official action repository refs verified the pinned releases:
      `actions/checkout` v4.4.0 at `11d5960a`, `actions/setup-go` v6.5.0 at
      `924ae3a1`, and `hashicorp/setup-terraform` v3.1.2 at `b9cd54a3`.
    - `actionlint` v1.7.12, the immutable-action pin validator, and
      `git diff --check` passed.
    - Formatting and `go generate ./...` drift checks passed; `go vet ./...`,
      `go test ./...`, `go test -race ./...`, and `go build ./...` passed.
    - The acceptance test passed separately with exactly
      `TF_ACC_TERRAFORM_1_10` pointing to Terraform 1.10.5 and exactly
      `TF_ACC_TERRAFORM_1_11` pointing to Terraform 1.11.4. CI selects the
      same single matching variable per matrix entry; provider tests contain
      no Terraform download path.
    - Remote GitHub Actions execution is pending the separately authorized
      push; no remote mutation was performed.
    - Runtime harness: local Terraform acceptance passed for 1.10.5 and
      1.11.4 (8.129s and 7.738s respectively).
    - Rollback boundary: remove `.github/workflows/ci.yml`; no provider runtime
      behavior or generated documentation changes were made.
    - Work-unit commit intent: `ci(provider): add pinned validation workflow`.

- [x] **PRP-002 — Signed release packaging**
  - Add GoReleaser v2 packaging with Registry-compatible archive names,
    versioned binaries, protocol manifest, SHA-256 checksums, and detached GPG
    checksum signature.
  - Add a tag-triggered, least-privilege GitHub release workflow that imports
    signing material only from GitHub Actions secrets.
  - Acceptance:
    - `goreleaser check` passes.
    - An unsigned local snapshot produces the expected archives, manifest, and
      checksums without publishing.
    - No private signing material is present or generated in the repository.
  - Route: delegated writer; writer trigger fired.
  - Evidence:
    - GoReleaser `v2.18.2` check and unsigned clean snapshot passed.
    - Snapshot produced 11 Registry-compatible ZIPs; each contains only the
      versioned provider binary. Checksums include every ZIP and the renamed
      protocol-6 manifest with its verified SHA-256.
    - Release workflow is tag-triggered, SHA-pinned, validates SemVer, marks
      prereleases automatically, and grants `contents: write` only to its job.
    - Signing key/passphrase enter only through GitHub secrets; no key was
      generated or stored. Detached binary GPG signing is configured.
    - Runtime harness: local cross-platform snapshot completed in 2m2s.
    - Rollback: remove `.goreleaser.yml` and `.github/workflows/release.yml`,
      and revert the `dist/` ignore entry; provider behavior is unchanged.

- [x] **PRP-003 — Operator documentation and final verification**
  - Document immutable tag/release procedure, required GitHub secrets, expected
    artifacts, prerelease pinning, and the explicit boundary before Terraform
    Registry registration.
  - Run the complete local verification suite and reconcile this ledger.
  - Acceptance:
    - Documentation matches the implemented workflows and current provider
      identity/version floor.
    - All applicable checks and snapshot inspection pass, with unavailable or
      skipped checks recorded honestly.
  - Route: delegated writer for documentation; parent performs final
    orchestration and evidence reconciliation.
  - Evidence:
    - `README.md` documents the dedicated RSA release-signing identity, the
      private/public-key trust boundary, exact workflow secrets, immutable tag
      procedure, expected Registry-compatible assets, GPG/checksum validation,
      and exact prerelease pinning (`= 0.1.0-rc.1`).
    - The documentation keeps Terraform Registry registration outside this
      pipeline as a later explicitly authorized operation and forbids moving
      published tags or replacing their assets.
    - `actionlint` v1.7.12 passed; all 10 workflow action references are pinned
      to 40-character commit SHAs; all 21 tracked Go files pass `gofmt`.
    - `go generate ./...` left generated provider documentation unchanged.
      `go vet ./...`, `go test ./...`, `go test -race ./...`, and
      `go build ./...` passed.
    - `TestTerraformEphemeralAcceptance` passed independently with Terraform
      1.10.5 and 1.11.4 (7.219s and 7.279s), with exactly one matching
      acceptance environment variable configured per run.
    - GoReleaser v2.18.2 required Go 1.27.1, so `GOTOOLCHAIN=auto` supplied the
      required toolchain; configuration validation and a clean unsigned
      snapshot passed. The snapshot produced 11 platform ZIPs containing one
      versioned executable each. The release manifest declares protocol 6.0,
      and every generated checksum passed after materializing the configured
      release extra file under its release name.
    - Repository and current-diff scans found no private-key blocks or common
      live-secret token patterns. `git diff --check` passed.
    - Intentionally skipped: checksum signing (no private key used), GitHub
      Actions execution, push, tag, GitHub release, and Terraform Registry
      registration. All require later remote authorization or secret setup.
    - Runtime harness: the two real Terraform CLI acceptance runs and the local
      cross-platform GoReleaser snapshot exercised the applicable boundaries.
    - Rollback boundary: remove the `Publishing a release` section from
      `README.md`; CI, packaging, and provider runtime behavior are unchanged.
    - Work-unit commit intent: `docs(release): document provider publication`.

## Progress

- CodeGraph mapping completed before filesystem inspection.
- Existing provider identity, protocol manifest, version injection point, and
  absence of CI/release configuration verified at commit `aeb308e`.
- Official HashiCorp and GoReleaser requirements mapped; no remote mutation was
  performed.
- PRP-001 implemented as a least-privilege, SHA-pinned workflow with isolated
  Terraform 1.10.5 and 1.11.4 acceptance jobs.
- Running authored change count before the PRP-001 commit: 237 additions and
  no deletions (generated artifacts excluded).
- PRP-002 packaging and local snapshot validation completed without publishing.
- PRP-003 operator procedure and full local verification completed without any
  remote mutation or use of release signing material.
- Final feature diff: 510 authored lines (510 additions, no deletions), excluding
  ignored snapshot artifacts. The user-approved `single-pr` exception applies
  to the complete feature.

## Next step

After explicit authorization, push `tfp-provider-release-pipeline` and verify
its GitHub Actions CI. Only then configure the signing secrets and separately
authorize creation of `v0.1.0-rc.1`. Terraform Registry registration and the
real GoVault workload-auth smoke test remain later explicit steps.
