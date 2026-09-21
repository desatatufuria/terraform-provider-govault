# Native AppRole authentication for the Terraform provider

## Status

- Feature: in progress
- Current task: `PGA-002`
- Branch: `tfp-g-provider-approle-auth`
- Base: local `main` at `9ac3fff3018b194f44ad1a980bb6854d960143a4`
- Delivery strategy: `single-pr` (existing user preference)
- Forecast: 540–840 authored lines across three work units
- Size policy: the existing single-PR choice is retained; each work unit remains
  independently reviewable and below the per-unit planning heuristic.
- Remote delivery: not authorized

## Objective

Allow the standalone Terraform provider to authenticate natively with a
durable GoVault AppRole and obtain a short-lived, memory-only GoVault token.

## Problem and why

The provider currently supports direct token and workload assertion modes.
Unattended environments without an external OIDC issuer can use AppRole in
GoVault, but Terraform must currently obtain a token out of band. Native
AppRole login closes that gap without putting RoleID, SecretID, or the issued
token into Terraform configuration, plans, or state.

## Authorized scope

- Add explicit `auth_method = "approle"` support.
- Read RoleID only from `GOVAULT_ROLE_ID` and SecretID only from
  `GOVAULT_SECRET_ID`.
- Add optional non-secret `approle_namespace` to select root or namespaced
  AppRole login.
- Perform exactly one AppRole login during provider configuration.
- Keep the issued token, namespace, and expiry only in memory.
- Reuse the existing ephemeral `govault_secret` resource.
- Add unit, provider, runtime acceptance, leak-canary, documentation, and
  generated-schema coverage.

## Constraints

- Do not accept RoleID or SecretID as Terraform schema attributes.
- Do not write credentials or issued sessions to plan, state, diagnostics,
  logs, examples, or generated documentation.
- Do not retry AppRole login automatically; a limited SecretID use may already
  have been consumed before an ambiguous failure.
- Do not fall back to token or workload authentication.
- Reject crossed-method selectors before reading credentials or making network
  calls.
- Do not change the GoVault backend in this feature.
- Do not push, create a PR, merge, publish, or deploy without separate user
  authorization.
- Keep `.codegraph/` untouched.

## Verified contracts

- Root login: `POST /auth/login`.
- Namespaced login: `POST /ns/:namespace/auth/login`.
- Request: `{"method":"approle","credentials":{"role_id":...,"secret_id":...}}`.
- Success contains equal non-empty `token` and `access_token`, namespace,
  creation time, and future expiry.
- GoVault AppRole tokens default to two hours and are configurable per role.
- Limited SecretID use is consumed atomically before token issuance; therefore
  provider replay/retry is unsafe.

## TDD and verification

- Effective TDD: **disabled**.
- Source: inherited GoVault program configuration recorded by the completed
  Phase F tracker (`strict_tdd: false`, `rules.apply.tdd: false`).
- Ordinary runner: `go test ./...`.
- Additional checks: `gofmt`, generated-doc drift, `go vet ./...`, focused race
  tests, provider build, Terraform 1.10/1.11 runtime acceptance, and
  `git diff --check` as applicable.
- Receipt-driven development: **enabled** globally; each work-unit commit is
  assessed against the previous reviewed boundary.

## Tasks

- [x] **PGA-001 — Add the bounded AppRole client exchange**
  - Route: delegated direct.
  - Trigger evidence: protocol client, response validation, session install,
    and exhaustive transport tests span multiple non-trivial files.
  - Acceptance:
    - Exact root and namespaced request paths and JSON body.
    - Exactly one request for success and every failure class.
    - Bounded response parsing with sanitized diagnostics.
    - Equal non-empty token aliases, namespace, and future expiry required.
    - Returned session remains memory-only and reusable by the existing client.
  - Checks: focused client tests, `go test ./internal/client`, race, formatting.
  - Evidence:
    - `Client.LoginAppRole` implements one root or namespaced request with no
      retry, bounded response parsing, sanitized failures, strict token aliases,
      namespace, creation, and expiry validation.
    - `Client.InstallAppRoleSession` atomically installs only a valid in-memory
      bearer, namespace, and expiry for existing secret reads.
    - Tests cover exact root/namespaced contracts, invalid input before I/O,
      one-attempt status and transport failures, redaction, malformed/oversized
      responses, invalid session fields, and harmless server-ahead clock skew.
    - Focused: `go test ./internal/client -run 'TestLoginAppRole' -count=1`
      — passed.
    - Package: `go test ./internal/client` — passed.
    - Race: `go test -race ./internal/client -run 'TestLoginAppRole' -count=1`
      — passed.
    - Formatting: `gofmt` and `git diff --check` — passed.
    - Runtime harness: N/A; this work unit is the bounded HTTP client boundary.
      Terraform runtime acceptance belongs to `PGA-003`.
    - Rollback: remove `internal/client/approle_login_test.go` and only the
      AppRole additions in `internal/client/client.go`.
    - Work-unit commit: pending commit identity.

- [-] **PGA-002 — Wire explicit AppRole provider configuration**
  - Route: delegated direct.
  - Trigger evidence: schema, environment selection, configure flow, method
    matrix, and end-to-end provider tests span multiple non-trivial files.
  - Acceptance:
    - `auth_method = "approle"` is explicit.
    - Credentials come only from the fixed environment variables.
    - `approle_namespace` is the only public AppRole selector.
    - Missing, empty, crossed, or unknown inputs fail before network I/O.
    - Configure logs in once and publishes an authenticated memory-only client.
  - Checks: focused provider tests, `go test ./internal/provider`, race,
    formatting.
  - Evidence: pending.

- [ ] **PGA-003 — Prove runtime secrecy and document usage**
  - Route: delegated direct.
  - Trigger evidence: Terraform acceptance harness, leak canaries, examples,
    README, generated docs, and repository checks span multiple files.
  - Acceptance:
    - Terraform 1.10 and 1.11 configure AppRole and read an ephemeral secret.
    - RoleID, SecretID, issued token, and response bodies are absent from plan,
      show, apply output, state, logs, diagnostics, examples, and docs.
    - User documentation explains durable AppRole versus short-lived token and
      the no-retry behavior.
  - Checks: full tests, acceptance matrix, generation drift, vet, build,
    formatting.
  - Evidence: pending.

## Progress and next step

`PGA-001` is implemented and locally verified. Implement `PGA-002` next; no
remote operation is authorized.
