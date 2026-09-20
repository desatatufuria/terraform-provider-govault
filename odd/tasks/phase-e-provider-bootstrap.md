# Phase E Provider Bootstrap

## Objective

Deliver a standalone, protocol-6 Terraform provider that can authenticate with a pre-issued GoVault token and read one secret through a Terraform ephemeral resource without persisting provider-owned secret material.

## Problem

GoVault now exposes the backend and administration boundaries needed by a future universal Terraform integration, but no dedicated provider repository exists. Phase E must establish the provider and its state-safety boundary before workload identity is added in Phase F.

## Why

Terraform needs a conventional, independently releasable provider whose first capability is safe on Terraform 1.10+: explicit token bootstrap, normal TLS verification, server-derived namespace authority, and an ephemeral-only secret result.

## Authorized scope

The user authorized local Phase E implementation in this dedicated repository. This includes repository bootstrap, protocol-6 provider wiring, token bootstrap from an environment variable, bounded TLS/client behavior, `/auth/whoami` namespace discovery, one `govault_secret` ephemeral resource, generated documentation, tests, and leak checks.

It does not authorize a remote repository, push, pull request, release, GoVault backend changes, workload assertion authentication, Phase F, Proxmox access, OpenTofu certification, or changes to GoVault `develop`.

## Frozen contracts

- Registry address: `registry.terraform.io/desatatufuria/govault`.
- Go module: `github.com/desatatufuria/terraform-provider-govault`.
- Terraform product floor: 1.10; protocol 6 remains distinct from that floor.
- Authentication is explicit: Phase E supports only `auth_method = "token"`.
- Token material comes from the named environment variable `GOVAULT_TOKEN`; no inline token schema and no fallback exist.
- Provider schema exposes non-secret selectors only: `address`, `auth_method`, `token_env`, and optional `ca_cert_file`.
- Normal TLS certificate and hostname verification are mandatory; a custom CA is explicit and file-based.
- `/auth/whoami` derives the namespace bound to the session.
- `govault_secret` accepts `path` and optional positive `version`; it cannot select namespace, policy, role, or authentication authority.
- Secret results are computed, sensitive, and ephemeral. No secret-bearing data source or managed resource exists.
- Phase E implements `Open`; no lease renewal is invented. Close only clears local references where the Framework lifecycle makes that useful.

## TDD and verification

- Effective TDD: disabled.
- Source: the approved GoVault program configuration `openspec/config.yaml` (`strict_tdd: false`, `rules.apply.tdd: false`).
- No RED evidence will be invented.
- Primary runner: `go test ./...`; focused package tests run before broader race, vet, build, formatting, protocol, documentation, and leak checks.
- Terraform acceptance needs pinned 1.10 and 1.11 binaries. Neither Terraform nor OpenTofu is currently installed; unavailable checks must remain explicit until the local tool gate is satisfied.

## Delivery and routing

- Forecast: 900–1,300 authored changed lines across three cohesive work units.
- Delivery strategy: `feature-branch-chain`.
- Local branch: `tfp-e-provider-bootstrap`, created from empty repository baseline `02c3a98`.
- PHE-001 route: delegated direct; mapping, preparation, and writer triggers apply because the scaffold spans multiple non-trivial files.
- PHE-002 route: delegated direct; security-sensitive client behavior spans provider and HTTP boundaries.
- PHE-003 route: delegated direct; resource, acceptance, docs, and leak evidence span multiple files.
- Each task closes with a Conventional Commit containing its tests and documentation.
- RDD is enabled globally; each committed work unit uses its exact native candidate assessment.

## Tasks

- [x] **PHE-001 — Repository gate and protocol-6 scaffold**
  - Pin the current official Terraform Plugin Framework dependency baseline without `latest` or branch dependencies.
  - Add protocol-6 provider server, provider metadata/schema/configuration, provider factories, Registry protocol manifest, minimal examples, and repository documentation.
  - Keep schema free of secret-valued attributes and reject unsupported authentication methods or unsafe unknown configuration.
  - Prove exact Registry address, Terraform 1.10 floor documentation, offline validation, and nil provider-data safety.
- [-] **PHE-002 — Bounded GoVault token client**
  - Read the token only from the explicitly named environment variable.
  - Build a cancellation-aware, timeout-bounded HTTP client with default TLS verification and optional PEM CA file.
  - Call `/auth/whoami`, derive the session namespace, and translate stable error classes without copying response bodies, tokens, or secret values into diagnostics.
  - Prove missing-token, no-fallback, custom-CA, hostname failure, timeout, cancellation, and redaction behavior.
- [ ] **PHE-003 — Ephemeral secret and state-safety evidence**
  - Implement `govault_secret` with required `path`, optional positive `version`, and computed sensitive ephemeral result fields.
  - Read through the namespace derived from the session and the slash-safe secret endpoint; never expose namespace selection.
  - Add protocol/unit tests, pinned Terraform 1.10/1.11 acceptance harness, generated Registry docs, examples, and canary scans across plan, state, JSON, stdout/stderr, diagnostics, logs, artifacts, and docs.
  - Record any acceptance checks unavailable because pinned Terraform binaries are absent; never substitute a state-bearing resource or data source.

## Acceptance criteria

- `go test ./...`, `go test -race ./...`, `go vet ./...`, `go build ./...`, `gofmt`, and `git diff --check` pass.
- The provider serves protocol 6 at the exact approved Registry address.
- Configuration cannot contain an inline token and never silently selects another authentication method.
- Unknown/null configuration is handled explicitly; provider and ephemeral offline validation tolerate nil provider data.
- Token, response bodies, and secret values never enter diagnostics, logs, generated docs, plan, state, or test artifacts.
- Namespace authority comes only from `/auth/whoami`; the ephemeral resource cannot override it.
- Secret paths containing `/` are transmitted as query values, and omitted version means latest while non-positive versions fail locally.
- TLS fails closed without a trusted CA and on hostname mismatch; explicit custom CA, cancellation, and timeout behavior are tested.
- Terraform 1.10 and 1.11 acceptance evidence is pinned and reproducible before Phase E can close.
- Rollback removes only the unreleased provider branch; GoVault remains unchanged.

## Evidence and progress

- GoVault source contract: `docs/terraform-provider-govault-phase-0-contract.md`, sections 4, 9, 12, and 14.
- GoVault delivery plan: `docs/terraform-provider-govault-delivery-plan.md`, Phase E.
- Verified backend boundary: bearer middleware, `/auth/whoami`, and namespaced slash-safe secret reads already exist in GoVault.
- Official HashiCorp documentation confirms protocol 6 provider servers and Terraform 1.10 ephemeral resources; protocol compatibility alone does not provide the product's no-state guarantee.
- Repository gate: local repository initialized without a remote at baseline `02c3a98`; implementation branch `tfp-e-provider-bootstrap` is active.
- CodeGraph initialized for this repository before structural work.
- PHE-001 implementation: `36646ff` (`feat(provider): scaffold protocol 6 provider`), 12 files and 676 changed lines including generated `go.sum`; protocol-6 scaffold, non-secret provider schema, manifest, examples, generated documentation, and offline configuration tests.
- PHE-001 verification: focused provider and protocol/repository tests, `go test ./...`, `go test -race ./...`, `go vet ./...`, `go build ./...`, `gofmt`, `go mod verify`, `go mod tidy -diff`, and `git diff --check` pass. The direct protocol test uses `providerserver.NewProtocol6WithError` and `GetProviderSchema`; no Terraform acceptance runtime is claimed.
- PHE-001 RDD: frozen candidate `36646ff` was approved and acknowledged under `review-5f66995eb36334c6`. Reliability finding `R3-MODULE-TIDY` identified that the directly imported `terraform-plugin-go` module was classified as indirect; the PHE-001 closure correction ran `go mod tidy`, made it direct, and left `go mod tidy -diff` empty.
- PHE-001 rollback: revert the closure correction first, then revert `36646ff`; GoVault remains unchanged.

## Next step

Implement PHE-002 only. Keep PHE-003 pending until the bounded token client work unit is verified, committed, and assessed.
