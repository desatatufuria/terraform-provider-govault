# Phase F — Product-neutral workload authentication

## Status

- Phase: authorized for local implementation planning
- Current task: `PFF-001` pending
- Branch: `tfp-f-provider-workload-auth`
- Base: `main` at `139bc0f8ced45c169975ae3f5c581583874ba444`
- Delivery strategy: `feature-branch-chain`
- Forecast: 1,160–1,740 authored lines across four work units
- Remote delivery: not authorized

## Objective

Allow the standalone Terraform provider to authenticate to GoVault with a
product-neutral external workload assertion, without requiring a static
GoVault token, while preserving the existing explicit direct-token mode.

## Problem

Phase E supports only a bearer token read from one named environment variable.
GoVault Phase C already exposes a public workload exchange, but the provider
cannot yet select an assertion source, exchange it for a short-lived GoVault
session, retain that session only in memory, or reauthenticate safely when it
expires.

## Why

External automation needs a generic workload identity path that is not tied to
GitHub, GitLab, Kubernetes, AppRole, or any other product. The provider must
consume the stable server contract without moving namespace, policy, issuer,
audience, algorithm, or TTL authority to Terraform configuration.

## Authorized scope

- Extend the standalone provider with explicit `token` and `workload`
  authentication modes.
- Read workload assertions from exactly one named environment variable or one
  protected file.
- Exchange `{role_ref, assertion}` through `POST /auth/workload/login`.
- Keep the resulting GoVault session token, namespace, and expiry in memory.
- Reauthenticate in the bounded cases defined below.
- Continue serving the existing ephemeral `govault_secret` boundary.
- Add provider-local contract fixtures, unit tests, Terraform 1.10/1.11 runtime
  acceptance, leak canaries, documentation, and examples.

## Out of scope

- GoVault source or API changes.
- GitHub-, GitLab-, Kubernetes-, CI-, cloud-, or vendor-specific helpers.
- AppRole, Kubernetes auth, automatic method discovery, or method fallback.
- Inline assertions or inline static GoVault tokens in provider configuration.
- Commands or shell hooks that obtain assertions.
- Persistent Terraform resources or data sources for secrets.
- Phase G, Proxmox, OpenTofu, release, push, pull request, or remote delivery.

## Frozen contracts and decisions

### GoVault workload exchange

- Endpoint: `POST /auth/workload/login`; there is no namespaced variant.
- Request contains only `role_ref` and `assertion`.
- Assertion maximum is 262,144 bytes.
- Provider, namespace, policies, TTL, issuer, audience, and algorithm remain
  server-authoritative.
- The successful response contains equal non-empty `token` and `access_token`,
  namespace, identity metadata, policies, creation time, and expiry.
- Workload tokens have no refresh token. A new session requires a fresh
  assertion and a new exchange.
- Public failures remain `400`, `401`, `429`, and `503`; raw response bodies
  must never become provider diagnostics.

### Provider schema

- `auth_method` is explicit and accepts only `token` or `workload`.
- Existing token mode keeps `token_env` and never falls through to workload.
- Workload mode uses these public attributes:
  - `workload_role_ref`
  - `workload_assertion_env`
  - `workload_assertion_file`
- Workload mode requires exactly one assertion source.
- Token-only selectors are rejected in workload mode; workload-only selectors
  are rejected in token mode. No configured selector is silently ignored.

### Assertion sources

- Environment mode reads only the explicitly named variable and has no
  fallback variable.
- Unix file mode accepts only a regular file, rejects symlinks, limits content
  to 262,144 bytes, and rejects group or other permission bits.
- Windows supports environment assertions only; file mode fails closed with a
  stable diagnostic.
- Assertions are read on demand, bounded, validated as non-empty UTF-8 input,
  and are not retained in provider state after the exchange completes.

### Session and reauthentication

- Workload login does not perform a follow-up `/auth/whoami` call.
- The provider stores only the GoVault bearer, namespace, expiry, and internal
  coordination metadata in memory.
- Reauthentication occurs only when known expiry has been reached or after one
  authenticated secret read returns `401`.
- Concurrent reauthentication is coordinated so one exchange establishes the
  next session generation.
- At most one exchange and one replay are allowed for the affected operation.
- Login itself is not retried automatically after `401`.
- There is never fallback to token auth or to another assertion source.
- Cancellation and configured HTTP timeouts apply to exchange and replay.

### Contract fixture

- A versioned workload-login fixture lives in this provider repository.
- It validates the frozen request, response, status, and additive-response
  compatibility without creating a runtime dependency on the GoVault repo.

## Architecture boundary

The provider owns source selection and session lifecycle. The HTTP client owns
bounded protocol calls and TLS. The ephemeral resource consumes an authenticated
client/session boundary; it does not know how the assertion was obtained and
never receives auth selectors.

```text
Terraform provider configuration
  -> explicit auth method validation
  -> selected bounded credential source
  -> workload exchange client
  -> in-memory GoVault session
  -> ephemeral govault_secret read
```

## TDD and verification mode

- TDD: disabled by the GoVault program configuration
  (`openspec/config.yaml`: `strict_tdd: false`, `rules.apply.tdd: false`).
- Test runner: `go test ./...`.
- Ordinary behavior-first verification remains mandatory for every work unit.
- RDD: enabled globally at planning time; each committed work unit is assessed
  against the previous reviewed boundary.

## Work units

### PFF-001 — Explicit modes and bounded assertion sources `[ ]`

Route: `delegated direct`.

Trigger evidence: preparation and mapping span provider schema, configuration,
client construction, tests, documentation, and platform-specific file behavior;
implementation will touch multiple non-trivial files.

Scope:

- Extend schema and configuration validation for the frozen attributes.
- Preserve direct-token behavior exactly.
- Implement explicit environment and protected-file assertion sources.
- Add Unix and Windows behavior behind small platform-specific boundaries.
- Document the selectors and negative combinations.

Acceptance:

- Every token/workload selector combination is covered.
- Null, unknown, empty, dual-source, wrong-method, symlink, non-regular,
  oversized, and unsafe-permission inputs fail closed before network I/O.
- Missing selected environment variables never fall back.
- Diagnostics do not contain assertion content.

Forecast: 280–420 authored lines.

### PFF-002 — Workload exchange protocol `[ ]`

Route: `delegated direct`.

Trigger evidence: the HTTP client, DTO boundary, contract fixture, tests, and
documentation are multiple non-trivial files.

Scope:

- Add the bounded `POST /auth/workload/login` client operation.
- Preserve TLS, custom CA, hostname verification, timeout, cancellation, and
  redirect rejection from Phase E.
- Validate the frozen success response and stable failure classes.
- Add a versioned provider-local contract fixture.

Acceptance:

- Exact allowlisted request body; no namespace, policy, TTL, provider, issuer,
  audience, or algorithm fields.
- Response body is bounded and exactly one JSON value; additive fields remain
  compatible.
- Tokens are non-empty and equal, namespace is non-empty, and expiry is valid.
- `400`, `401`, `429`, `503`, malformed, oversized, trailing, timeout,
  cancellation, redirect, CA, and hostname cases are covered.
- Bodies, assertions, bearer tokens, URLs, and secrets are absent from errors.

Forecast: 280–420 authored lines.

### PFF-003 — Memory-only session and bounded reauthentication `[ ]`

Route: `delegated direct`.

Trigger evidence: provider configuration, client/session coordination,
ephemeral reads, concurrency tests, and lifecycle documentation span multiple
non-trivial files.

Scope:

- Introduce the smallest provider-local session coordinator.
- Wire token mode and workload mode through explicit construction paths.
- Re-read the selected assertion only at initial login or allowed reauth.
- Coordinate one session generation and one replay across concurrent readers.
- Reuse the existing ephemeral secret resource contract.

Acceptance:

- Session material never enters schema, plan, state, resource results, or
  diagnostics.
- Known expiry and one secret-read `401` trigger one coordinated exchange.
- `403`, `429`, `5xx`, malformed responses, TLS failures, and cancellation do
  not trigger method/source fallback or uncontrolled replay.
- Concurrent tests prove bounded exchanges and correct session generations.
- Direct-token mode remains behaviorally unchanged.

Forecast: 280–420 authored lines.

### PFF-004 — Runtime acceptance, leak canaries, and user documentation `[ ]`

Route: `delegated direct`.

Trigger evidence: external-process Terraform harness, fake GoVault protocol,
fixtures, examples, generated documentation, and artifact scanning require
multiple non-trivial files.

Scope:

- Extend the verified Terraform 1.10.5 and 1.11.4 acceptance matrix.
- Exercise successful workload login, ephemeral secret read, expiry/401 reauth,
  and negative no-fallback behavior.
- Add separate assertion, forbidden-static-token, session-token, and secret
  canaries.
- Update provider documentation and examples without real credentials.

Acceptance:

- Both Terraform versions pass against the committed candidate.
- Plan, show, apply, state, stdout, stderr, `TF_LOG`, temporary artifacts,
  diagnostics, examples, and generated docs are scanned.
- No canary or raw HTTP body is present on any scanned surface.
- The fake server verifies exact bearer generations and request counts.
- No runtime dependency on the GoVault checkout exists.

Forecast: 320–480 authored lines.

## Required checks

Per applicable work unit and again at the integration boundary:

```bash
go test ./internal/client ./internal/provider
go test ./...
go test -race ./...
go vet ./...
go build ./...
go mod verify
go mod tidy -diff
gofmt -l .
git diff --check
```

Runtime acceptance for PFF-004 must use the already verified local Terraform
1.10.5 and 1.11.4 binaries and record exact commands, candidate commit/tree,
results, log hashes, and scanned surfaces. An unavailable runtime is reported;
it is never represented as passed.

## Security canaries

- External assertion.
- A static GoVault token that must never be consulted in workload mode.
- Workload exchange session token.
- Secret value returned by `govault_secret`.

The canaries must be distinct and absent from state, plan, JSON, logs,
diagnostics, process output, temporary artifacts, documentation, and examples.

## Evidence ledger

| Task | Commit | Authored lines | Checks | Runtime | RDD | Rollback |
| --- | --- | ---: | --- | --- | --- | --- |
| Planning | pending | pending | `git diff --check` pending | N/A: documentation-only work unit | assessment pending | revert planning commit |
| PFF-001 | pending | pending | pending | N/A unless a runtime boundary is introduced | pending | revert PFF-001 work-unit commit(s) |
| PFF-002 | pending | pending | pending | focused fake-server protocol tests | pending | revert PFF-002 work-unit commit(s) |
| PFF-003 | pending | pending | pending | focused concurrent session/replay tests | pending | revert PFF-003 work-unit commit(s) |
| PFF-004 | pending | pending | pending | Terraform 1.10.5/1.11.4 matrix | pending | revert PFF-004 work-unit commit(s) |

## Delivery and rollback

- Chain strategy: `feature-branch-chain`.
- Each PFF task is a cohesive work-unit commit or review slice with its tests and
  documentation.
- The reviewed boundary advances only according to native RDD results.
- No pull request, push, merge, or release is implied by local completion.
- Roll back a task by reverting its recorded commit(s) in reverse order.
- Roll back all Phase F work by reverting the Phase F chain back to base
  `139bc0f8ced45c169975ae3f5c581583874ba444` without altering Phase E history.

## Progress

- [x] Read-only Phase F exploration completed against provider Phase E and
  GoVault Phase C.
- [x] Public schema, source policy, session policy, contract ownership, branch,
  delivery strategy, and work-unit boundaries frozen.
- [ ] PFF-001 — Explicit modes and bounded assertion sources.
- [ ] PFF-002 — Workload exchange protocol.
- [ ] PFF-003 — Memory-only session and bounded reauthentication.
- [ ] PFF-004 — Runtime acceptance, leak canaries, and user documentation.

## Next step

Implement only `PFF-001` under the delegated-direct route. Do not begin PFF-002
until PFF-001 has a committed candidate, recorded checks, and the required RDD
assessment outcome.
