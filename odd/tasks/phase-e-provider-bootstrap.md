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
- Terraform acceptance uses locally cached, cryptographically verified official Terraform 1.10.5 and 1.11.4 Linux amd64 binaries. OpenTofu remains outside the Phase E certification scope.

## Delivery and routing

- Forecast: 900–1,300 authored changed lines across three cohesive work units.
- Delivery strategy: `feature-branch-chain`.
- Source branch `tfp-e-provider-bootstrap`, created from empty repository baseline `02c3a98`, was integrated locally into `main` by merge `693e1ed`.
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
- [x] **PHE-002 — Bounded GoVault token client**
  - Read the token only from the explicitly named environment variable.
  - Build a cancellation-aware, timeout-bounded HTTP client with default TLS verification and optional PEM CA file.
  - Call `/auth/whoami`, derive the session namespace, and translate stable error classes without copying response bodies, tokens, or secret values into diagnostics.
  - Prove missing-token, no-fallback, custom-CA, hostname failure, timeout, cancellation, and redaction behavior.
- [x] **PHE-003 — Ephemeral secret and state-safety evidence**
  - Implement `govault_secret` with required `path`, optional positive `version`, and computed sensitive ephemeral result fields.
  - Read through the namespace derived from the session and the slash-safe secret endpoint; never expose namespace selection.
  - Add protocol/unit tests, pinned Terraform 1.10/1.11 acceptance harness, generated Registry docs, examples, and canary scans across plan, state, JSON, stdout/stderr, diagnostics, logs, artifacts, and docs.
  - Record pinned acceptance evidence truthfully; never substitute a state-bearing resource or data source.

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
- Rollback of the local integration is `git revert -m 1 693e1ed` on `main`; its inverse diff restores the empty baseline tree `4b825dc642cb6eb9a060e54bf8d69288fbee4904`, and GoVault remains unchanged. This command is documented only and has not been executed.

## Evidence and progress

- GoVault source contract: `docs/terraform-provider-govault-phase-0-contract.md`, sections 4, 9, 12, and 14.
- GoVault delivery plan: `docs/terraform-provider-govault-delivery-plan.md`, Phase E.
- Verified backend boundary: bearer middleware, `/auth/whoami`, and namespaced slash-safe secret reads already exist in GoVault.
- Official HashiCorp documentation confirms protocol 6 provider servers and Terraform 1.10 ephemeral resources; protocol compatibility alone does not provide the product's no-state guarantee.
- Repository gate: local repository initialized without a remote at baseline `02c3a98`; merge `693e1ed` integrates source head `5da7655` into local `main`, and both share tree `016af643e79aad726258f24e9f3bad35313ed55a`.
- CodeGraph initialized for this repository before structural work.
- PHE-001 implementation: `36646ff` (`feat(provider): scaffold protocol 6 provider`), 12 files and 676 changed lines including generated `go.sum`; protocol-6 scaffold, non-secret provider schema, manifest, examples, generated documentation, and offline configuration tests.
- PHE-001 verification: focused provider and protocol/repository tests, `go test ./...`, `go test -race ./...`, `go vet ./...`, `go build ./...`, `gofmt`, `go mod verify`, `go mod tidy -diff`, and `git diff --check` pass. The direct protocol test uses `providerserver.NewProtocol6WithError` and `GetProviderSchema`; no Terraform acceptance runtime is claimed.
- PHE-001 RDD: frozen candidate `36646ff` was approved and acknowledged under `review-5f66995eb36334c6`. Reliability finding `R3-MODULE-TIDY` identified that the directly imported `terraform-plugin-go` module was classified as indirect; the PHE-001 closure correction ran `go mod tidy`, made it direct, and left `go mod tidy -diff` empty.
- PHE-001 rollback: revert the closure correction first, then revert `36646ff`; GoVault remains unchanged.
- PHE-002 contract verification: GoVault registers `GET /auth/whoami` on the bearer-authenticated `authSession` group in `config/wiring.go`; `internal/api/middleware/auth.go` consumes `Authorization: Bearer <token>`, and `internal/api/handlers/whoami.go` returns the normalized principal namespace. This matches the frozen provider contract.
- PHE-002 implementation: the provider reads only the environment variable selected by `token_env` (default `GOVAULT_TOKEN`), rejects missing values without fallback, builds an HTTPS-only client with normal hostname verification, optional PEM CA roots, TLS 1.2 minimum, and a 30-second timeout, then derives namespace authority from `/auth/whoami`. Only ephemeral provider data is configured; no resource or secret read was added.
- PHE-002 safety evidence: tests cover selected/default environment lookup, no fallback, custom and untrusted CA behavior, hostname mismatch, timeout, caller cancellation, bearer request shape, namespace derivation, stable status/response failures, and redaction of token, transport, and response-body canaries from client errors and provider diagnostics.
- PHE-002 verification: focused client/provider/repository tests, repeated focused tests, `go test ./...`, `go test -race ./...`, `go vet ./...`, `go build ./...`, `gofmt`, `go mod verify`, `go mod tidy -diff`, generated documentation, and `git diff --check` pass. No Terraform acceptance runtime is claimed in PHE-002.
- PHE-002 review correction: `e38f1a7` (`fix(provider): harden token bootstrap boundaries`), 71 changed lines. Redirects are rejected before any bearer can be forwarded, the client installs an independent verified `tls.Config` rather than inheriting ambient `InsecureSkipVerify`, and `/auth/whoami` enforces a strict total response-size boundary while rejecting trailing JSON or content.
- PHE-002 correction verification: focused redirect/TLS/body-boundary tests, `go test ./internal/client -count=20`, `go test ./...`, `go test -race ./...`, `go vet ./...`, `go build ./...`, `go mod verify`, `go mod tidy -diff`, `gofmt`, and `git diff --check` pass.
- PHE-002 RDD: lineage `review-b730519481aa1728` reached final verdict `APPROVED`; the review was acknowledged and its authority consumed after validating corrected target `sha256:6a7c399afd50203d86c481385da6d6e2e4c8f3443d7245b00c33ab9162846808`.
- PHE-002 rollback: revert its work-unit commit; PHE-001 and GoVault remain unchanged.
- PHE-003 implementation is split across `836663f` (`feat(provider): read secrets ephemerally`) and `7a846d4` (`test(provider): add ephemeral leak canaries`). It adds the single `govault_secret` ephemeral resource, bounded slash-safe reads under the authenticated namespace, generated documentation, and a local-binary-only Terraform acceptance harness.
- PHE-003 warning hardening: `62b09da` (`fix(provider): harden ephemeral acceptance`), 270 changed lines. It fails closed on an unknown requested version and on a requested/returned version mismatch; uses a valid Terraform 1.10/1.11 fixture without a root ephemeral output; removes the provider-installation `direct {}` fallback; propagates `filepath.Walk` failures; terminates the Unix process group on timeout with a bounded non-Unix fallback; requires the exact bearer canary at the fake server; and proves diagnostic redaction with a secret-bearing HTTP 500 response.
- PHE-003 hardening RDD: lineage `review-8d1a763393aab530` reached final verdict `APPROVED`; the review was acknowledged and its authority consumed for candidate `62b09da` after read-only verification of the seven corrections.
- PHE-003 portability notes are acceptance-harness risks, not provider defects: the non-Unix fallback cannot guarantee descendant-process termination; Unix cleanup has an edge case if the Terraform leader exits before a descendant; Windows environment-key case folding and native path escaping remain unverified. A source/test comment that calls Terraform the provider process also remains pending outside this ledger-only commit.
- PHE-003 historical runtime diagnosis before `d946466`: verified official Terraform 1.10.5 and 1.11.4 binaries both passed `version -json` and failed at the first `plan`; the existing helper hid the underlying Terraform diagnostic. The harness was updated to report the failing subcommand with bounded output after explicit token/secret-canary redaction, with a negative regression test. This diagnostic-only change did not alter provider behavior, initialization, or the fixture.
- PHE-003 diagnostic hardening replaces raw-output publication with allowlisted structured signals, sanitizes command/class metadata, captures bounded head/tail data from the child process, normalizes invalid UTF-8 and terminal controls, and scans the entire stream for protected canaries including split writes. Tests cover an unknown arbitrary secret, hostile metadata, large output, split canaries, invalid UTF-8, ANSI, and control bytes.
- PHE-003 safe-diagnostic runtime diagnosis before the fixture correction emitted only `terraform plan failed (exit status 1); diagnostics: Invalid character, Invalid single-argument block definition`; its preserved log contained no protected canaries and isolated the HCL error later corrected by `d946466`.
- PHE-003 fixture correction: `d94646619a4b8155b122e85e522703fb1d7fb1a6` (`test(provider): fix ephemeral acceptance fixture`), candidate tree `361246bf31d12cab015953b4dc836d416181b88f`. It replaces the invalid semicolon-separated single-line HCL with equivalent multiline HCL without altering provider behavior or the acceptance scenario.
- PHE-003 runtime matrix command: `TF_ACC_TERRAFORM_1_10=/home/furia/.cache/govault-terraform-acceptance/1.10.5/terraform TF_ACC_TERRAFORM_1_11=/home/furia/.cache/govault-terraform-acceptance/1.11.4/terraform go test . -run '^TestTerraformEphemeralAcceptance$' -count=1 -v`.
- PHE-003 pinned runtime evidence: Terraform 1.10.5 at `/home/furia/.cache/govault-terraform-acceptance/1.10.5/terraform` has SHA-256 `971d83d156b45f42f64775bd1cfc5eec5822bfeaf422d195ec24842acd4be64e`; Terraform 1.11.4 at `/home/furia/.cache/govault-terraform-acceptance/1.11.4/terraform` has SHA-256 `268000fca5c61021c6396893d9483007ba589ad9d0aaccbd7dfa8c78bf7dbe23`.
- PHE-003 runtime result: both Terraform 1.10.5 and 1.11.4 matrix cases pass. The preserved log `/home/furia/.cache/govault-terraform-acceptance/phe-003-runtime-matrix-fixture-fix.log` has SHA-256 `2806b275af779c3bef82425a637ab9df9e15e5f2ca9f88501978b90e2bdcb717` and contains no protected token or secret canaries.
- PHE-003 state-safety surfaces: the harness exercises `plan`, plan JSON via `show -json`, `apply`, `state pull`, the expected secret-bearing HTTP 500 path, Terraform stdout/stderr and trace log, the complete temporary artifact tree, and repository README/docs/examples. Canary scans pass, and the negative HTTP 500 path proves `Ephemeral Open` reaches the GoVault read boundary.
- PHE-003 final RDD: lineage `review-d2b689f736515394` reviewed candidate `d946466` and reached `APPROVED`; its approval was acknowledged and the authority consumed. Non-blocking follow-ups are stronger formal provenance binding between the receipt, candidate, exact binary hashes, command, and log, plus an explicit successful-read counter in the positive acceptance path.
- Phase E integration RDD: lineage `review-7487aee00d19db1c` found `R3-POST-MERGE-ROLLBACK` in the original merge candidate. Correction `3cb9472` records the effective first-parent merge rollback; corrected target `sha256:2f6039dfa1af50551275af28e095ffcc49b1de56277a83c7f079d0231f270de4` reached `APPROVED`, was acknowledged, and its authority was consumed.
- Phase E is complete locally. This does not authorize or claim a remote repository, push, pull request, release, Phase F, or OpenTofu certification.

## Next step

Phase E is integrated and reviewed locally. The next step is the user's decision between remote delivery or opening Phase F; neither is authorized by this ledger closure.
