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
- Delivery strategy: `ask-on-risk`.
- Forecast: about 360 authored changed lines, excluding generated release
  artifacts.
- Initial reviewed boundary: `aeb308e1881d742de2a0958517c84571d7b0ece5`.
- RDD mode: enabled globally; assess each committed work unit.

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

- [-] **PRP-002 — Signed release packaging**
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
  - Evidence: pending.

- [ ] **PRP-003 — Operator documentation and final verification**
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
  - Evidence: pending.

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

## Next step

Implement and verify PRP-002 signed release packaging without publishing.
