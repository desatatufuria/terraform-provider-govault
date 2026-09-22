# Native AppRole authentication for the Terraform provider

## Status

- Feature: implementation complete
- Current task: publish the approved single pull request
- Branch: `feat/approle-auth`
- Base: local `main` at `9ac3fff3018b194f44ad1a980bb6854d960143a4`
- Delivery strategy: `single-pr` (existing user preference)
- Forecast: 540–840 authored lines across three work units
- Size policy: the user explicitly accepted `size:exception` for the cohesive
  single PR; each work unit remains independently reviewable.
- Approved issue: `#3` — `[Change]: add native AppRole authentication`
- Remote delivery: authorized on 2026-09-22 for publishing this branch and
  opening one pull request against `main`

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
    - Work-unit commit: `a10ac2bcd259b37abb9d0ca91a1377dec09da1ca`.

- [x] **PGA-002 — Wire explicit AppRole provider configuration**
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
  - Evidence:
    - Provider schema accepts explicit `auth_method = "approle"` and exposes
      only the non-secret `approle_namespace` selector; RoleID and SecretID do
      not exist in Terraform schema.
    - Configure reads `GOVAULT_ROLE_ID` and `GOVAULT_SECRET_ID` exactly once,
      rejects absent or empty credentials and crossed selectors before network
      I/O, then performs one login and installs the memory-only session.
    - Root and namespaced tests configure the provider and read a secret through
      the existing ephemeral client boundary; diagnostics redact credentials
      and response bodies.
    - Focused AppRole provider tests — passed.
    - Package: `go test ./internal/provider` — passed.
    - Race: focused AppRole provider tests with `-race` — passed.
    - Broader: `go test ./...` — passed.
    - Formatting: `gofmt` and `git diff --check` — passed.
    - Runtime harness: N/A; Terraform 1.10/1.11 execution belongs to
      `PGA-003`.
    - Rollback: remove only the AppRole schema/configure branches and AppRole
      cases from `internal/provider/provider.go` and `provider_test.go`.
    - Work-unit commit: `4c4f3abebec83a351db4dfa8a48d8b04e29014c5`.

- [x] **PGA-003 — Prove runtime secrecy and document usage**
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
  - Evidence:
    - Terraform 1.10.5 and 1.11.4 runtime acceptance covers root and namespaced
      AppRole login, verified TLS, one login/read per `plan` and `apply`, and no
      additional authentication during `show` or `state pull`.
    - RoleID, SecretID, issued token, secret value, and raw response-body
      canaries remain absent from Terraform output, plans, state, TF_LOG,
      diagnostics, repository artifacts, examples, and documentation.
    - README and provider examples lead with the safe environment-only AppRole
      path, explain `approle_namespace`, durable identity versus short-lived
      tokens, and the deliberate no-retry rule for limited SecretIDs.
    - Runtime: `TF_ACC_TERRAFORM_1_10=... TF_ACC_TERRAFORM_1_11=...
      go test ./... -run '^TestTerraformEphemeralAcceptance$' -count=1` —
      passed for Terraform 1.10.5 and 1.11.4.
    - Full: `go test ./...`, `go test -race ./...`, `go vet ./...`, and
      `go build ./...` — passed.
    - Generation: `GOPROXY=file:///go/pkg/mod/cache/download GOSUMDB=off
      go generate ./...` reproduced the same diff without network access. An
      initial run with the wrong home-relative cache path failed before making
      changes and was corrected.
    - Formatting: `gofmt` and `git diff --check` — passed.
    - Rollback: revert only `acceptance_test.go`, `repository_test.go`,
      `README.md`, `examples/provider/provider.tf`, and generated
      `docs/index.md` AppRole additions.
    - Work-unit commit: `ab81d9f64493c18b3cc112ca7613a5db0ee6d332`.
    - Native RDD: approved and acknowledged under lineage
      `review-2c0f1583c7707623` for the exact committed candidate.
    - Advisory follow-up: the approved review recorded non-blocking warnings
      about stronger AppRole request negative controls, shell-history guidance,
      and whitespace-insensitive documentation guards. Native authority marked
      them informational; they are not part of this feature's authorized scope.

- [x] **PGA-004 — Validate AppRole against the development lab**
  - Route: delegated direct mapping with parent-owned remote execution.
  - Trigger evidence: the test crossed the provider repository, deployed
    backend contract, remote Compose runtime, Terraform 1.10/1.11, and cleanup.
  - Acceptance:
    - A bounded AppRole authenticates against the real development API.
    - Terraform 1.10 and 1.11 complete plan, show, apply, and state inspection.
    - RoleID, SecretID, issued tokens, and secret values remain absent from all
      Terraform artifacts and logs.
    - Temporary credentials, AppRole, secret, and namespace are removed.
  - Evidence:
    - The previous API `v4.4.0-rc.19` was incompatible because it issued
      non-expiring AppRole tokens. Backend branch commit
      `3900201dcd82636f246e16dbd6382017c5d2d772` was pushed and deployed as an
      API-only lab build `v4.4.0-rc.20`; health was OK and the UI container ID,
      image, and start time were unchanged.
    - Terraform 1.10.5 and 1.11.4 each completed `plan`, `show -json`, `apply`,
      and `state pull` against the verified HTTPS endpoint using only
      `GOVAULT_ROLE_ID` and `GOVAULT_SECRET_ID` for AppRole credentials.
    - Audit evidence recorded exactly four AppRole logins and four namespaced
      secret reads, matching separate plan/apply configuration in both versions.
    - Recursive binary-safe scans found no RoleID, SecretID, secret value, or
      GoVault bearer token in plan, state, command output, diagnostics, or
      `TF_LOG=TRACE` artifacts.
    - Cascade cleanup removed namespace `tf-live-20260922-073745`; local and
      remote credential/test files were deleted, and the API remained healthy.
    - Registry publication was not completed: the registry rejected the remote
      push with HTTP 401. The immutable API image remains local to the lab host;
      this does not affect the completed runtime proof but must be resolved
      before treating the RC as distributable.

## Progress and next step

`PGA-001` through `PGA-004` are complete. The provider implementation passed
native RDD and the real AppRole flow passed on Terraform 1.10.5 and 1.11.4.
Issue `#3` is approved. Remote delivery of `feat/approle-auth` as one pull
request against `main` is authorized and in progress; merge remains pending.
