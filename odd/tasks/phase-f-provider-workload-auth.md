# Phase F — Product-neutral workload authentication

## Status

- Phase: provider-side implementation complete; GoVault parity pending
- Current task: `PFF-004` provider-side work complete; GoVault parity pending
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

- GoVault runtime/API changes; test-only parity needs separate authorization.
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
- Unix file mode opens without following symlinks; the same descriptor supplies
  `Fstat` type, group/other mode and size checks plus the bounded 262,144-byte
  read. Path-level `Lstat` followed by `ReadFile` is forbidden.
- Windows supports environment assertions only; file mode fails closed with a
  stable diagnostic.
- Assertions are read on demand, bounded, validated as non-empty UTF-8 input,
  and are not retained in provider state after the exchange completes.

### Session and reauthentication

- Workload login does not perform a follow-up `/auth/whoami` call.
- The provider stores only the GoVault bearer, namespace, expiry, and internal
  coordination metadata in memory.
- Reauthentication occurs only when an injectable clock observes
  `expires_at <= now` before the request. An unexpected `401` is terminal and
  never triggers exchange/replay because expiry and revocation are indistinct.
- Each read captures the atomic session/generation, reuses a newer generation,
  or elects one exchange leader whose result is shared by waiters.
- Waiters cancel independently; exchange stops only when all leave, and every outcome clears in-flight state.
- Results commit atomically only while their generation is current; stale results are discarded.
- One operation makes at most one login attempt. There is no internal sleep or
  retry for `400`, `401`, `429`, `503`, TLS, transport, timeout, cancellation,
  or malformed responses.
- There is never fallback to token auth or to another assertion source.
- Cancellation and configured HTTP timeouts apply to exchange and requests.

### Contract fixture

- The provider fixture records schema version, GoVault provenance and hash.
- Provider and GoVault validate the exact version/hash before completion/publication, without runtime coupling.

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

### PFF-001 — Internal workload exchange boundary `[x]`

Route: `delegated direct`.

Trigger evidence: the HTTP client, DTO boundary, contract fixture, tests, and
documentation are multiple non-trivial files.

Scope:

- Refactor transport construction so protocol calls do not require a static
  token, while preserving current token authentication behavior.
- Add the bounded `POST /auth/workload/login` operation without exposing
  `auth_method = workload` in provider schema yet.
- Add the versioned fixture/provenance/hash and GoVault parity-gate input.

Acceptance:

- Exact request body; bounded one-document additive-compatible response.
- Non-empty equal token aliases, namespace, and future expiry are required.
- Machine codes agree with `400/401/429/503`; parse ≤20 ASCII `Retry-After` bytes overflow-safe without retry.
- Exact request-count tests prove one login attempt for every failure class.
- Workload remains unreachable through public schema at this boundary.

Forecast: 280–420 authored lines.

### PFF-002 — Usable initial workload authentication `[x]`

Route: `delegated direct`.

Trigger evidence: provider schema, configuration, platform-specific assertion
sources, initial session construction, tests, and docs are multiple non-trivial
files.

Scope:

- Expose the frozen workload selectors and method validation.
- Implement env, descriptor-safe Unix file, and Windows env-only sources.
- Wire one initial workload exchange into `Configure`, publishing one atomic
  memory-only session to the existing ephemeral resource.
- Preserve `token_env = null` selecting the existing `GOVAULT_TOKEN` default.

Acceptance:

- Full per-method matrix: token null keeps its default; workload with both
  sources null fails; explicit empty, dual-source, crossed-method, and unknown
  values fail before network I/O.
- File tests cover no-follow, same-descriptor checks/read and path replacement.
- A valid workload configuration completes login and can read a secret; no
  public configuration is accepted without a functional path.
- No fallback or assertion/session material appears in diagnostics or state.

Forecast: 280–420 authored lines.

### PFF-003 — Memory-only session and bounded reauthentication `[x]`

Route: `delegated direct`.

Trigger evidence: provider configuration, client/session coordination,
ephemeral reads, concurrency tests, and lifecycle documentation span multiple
non-trivial files.

Scope:

- Introduce the smallest provider-local session coordinator.
- Wire token mode and workload mode through explicit construction paths.
- Re-read the selected assertion only at initial login or known-expiry reauth.
- Coordinate session generations under the frozen leader/waiter, cancellation,
  failed-flight cleanup, and stale-result rules.
- Reuse the existing ephemeral secret resource contract.

Acceptance:

- Session material never enters schema, plan, state, resource results, or
  diagnostics.
- `expires_at <= now` triggers one coordinated exchange using an injectable
  clock; an unexpected `401` is terminal and makes no login request or replay.
- `400`, `401`, `403`, `429`, `5xx`, malformed responses, TLS failures,
  timeout, and cancellation do not trigger fallback, sleep, or retry.
- Concurrent tests prove cancellation, cleanup, later retry, generation reuse,
  stale-result rejection, atomic commit and exact request counts.
- Direct-token mode remains behaviorally unchanged.

Forecast: 280–420 authored lines.

### PFF-004 — Runtime acceptance, leak canaries, and user documentation `[x]`

Route: `delegated direct`.

Trigger evidence: external-process Terraform harness, fake GoVault protocol,
fixtures, examples, generated documentation, and artifact scanning require
multiple non-trivial files.

Scope:

- Extend the verified Terraform 1.10.5 and 1.11.4 acceptance matrix.
- Exercise successful workload login, ephemeral secret read, known-expiry
  reauth, terminal unexpected `401`, and negative no-fallback behavior.
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
- Provider and separately authorized GoVault parity tests pass for the exact
  fixture version and hash before Phase F is declared complete.

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
| Planning | `2e8399e`, `1248044` | 440 | historical planning unit; current document passes `git diff --check` | N/A: documentation-only work unit | historical authority not recorded in this ledger | `git revert 1248044`; then `git revert 2e8399e` |
| PFF-001 | `97c9166` | 373 | focused/full/race/vet/build/mod/gofmt/diff PASS | fake TLS server proves exact one-attempt exchange; schema hidden | approved and consumed: `review-af4bcea9f41b811e`; one informational body-read cancellation warning deferred to later work | `git revert 71a7cd2`; `git revert 97c9166` |
| PFF-002 | `bf248f2`, `a603cbe`, `593a199` | 418, including the bounded correction | focused/full/race/vet/build/mod/gofmt/Windows compile/diff PASS | one initial workload login publishes a memory-only session; protected files reject FIFOs without blocking; the same client reads the namespaced secret with no whoami or fallback | approved and consumed: `review-ec31cc20a6e8cef4` | `git revert 593a199`; then `git revert a603cbe`; then `git revert bf248f2` |
| PFF-003 | `4f66151`, `b02e479` | 455, including the 93-line advisory follow-up | focused/full/repeated/race/vet/build/mod/gofmt/Windows compile/diff PASS | eight concurrent expired reads share one reauth; pre-canceled work performs zero credential I/O; waiter cancellation, failed-flight retry, real stale-generation rejection and terminal secret `401` verified | approved and consumed: `review-f501c5126a63eb76`; follow-up approved and consumed: `review-5ae809ae92b112cb` | `git revert b02e479`; then `git revert 4f66151` |
| PFF-004 | `d6cd027`, `2fecdcd`, `5a71860` | 395 excluding generated docs; 415 total | focused/full/race/vet/build/mod/tidy/generate/gofmt/Terraform fmt/diff PASS | Terraform 1.10.5/1.11.4 workload matrix PASS; exact lifecycle counts and leak scans PASS | approved and consumed: `review-9aec4c2f9412f982`; informational slow-runner timing advisory retained | `git revert 5a71860`; then `git revert 2fecdcd`; then `git revert d6cd027` |

PFF-001 functional rollback authority is `git revert 97c9166`; documentation commits preserve evidence history and are not an executable rollback sequence.
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
- [x] PFF-001 — Internal workload exchange boundary.
- [x] PFF-002 — Usable initial workload authentication.
- [x] PFF-003 — Memory-only session and bounded reauthentication, including the
  separate pre-cancel, diagnostic-classification, and stale-flight proof
  follow-up.
- [x] PFF-004 — Runtime acceptance, leak canaries, and user documentation.
- [ ] Run the separately authorized GoVault fixture parity test before declaring
  Phase F complete.

## Next step

Provider-side Phase F work is complete locally. Obtain separate authorization
to run the exact fixture version/hash parity test in GoVault before declaring
Phase F complete. No GoVault checkout was used by provider runtime acceptance.

## PFF-004 runtime evidence

- Candidate: commit `5a718603b1954b2b1df7ea1697d995f5f262beec`, tree
  `4056491f38eb7338061dd2b88f5c126b91f97750`.
- Runtime command:

  ```bash
  TF_ACC_TERRAFORM_1_10=/home/furia/.cache/govault-terraform-acceptance/1.10.5/terraform \
  TF_ACC_TERRAFORM_1_11=/home/furia/.cache/govault-terraform-acceptance/1.11.4/terraform \
  go test . -run '^TestTerraformEphemeralAcceptance$' -count=1 -v
  ```

- Both pinned versions passed. Per version, workload request counts were three
  successful logins, four successful secret reads, one terminal login and
  secret read, and one denied login with zero denied secret reads.
- Scanned surfaces: plan, show JSON, apply, state pull, bounded stdout/stderr,
  `TF_LOG`, the complete temporary tree, diagnostics, README, examples, and
  generated documentation.
- Final `TF_LOG` SHA-256 values:
  - Terraform 1.10.5: token `542dc7b4289b828300d85e69cd382daf4a892e4fa50ce32797cbf8139850800f`,
    workload success `bc88dc37fd1d4ee829fb0235902a06e8cddc42cbd211b0313aa0f15f855e937d`,
    terminal `92d777337036d54d720592a2caac3dd1bfc07e595ac3724c9972d88c76134751`,
    denied `59839eb40c8c78e0e5b54597c8943f0a811aee453980caf3cba1613b55fac5bb`.
  - Terraform 1.11.4: token `7c946a56d14fc62e4777c626e17335faae4e12612ed89e30480defc06f47fad6`,
    workload success `f2543fd68d2a9af50c032e117306bebe88867e088f95c7fafb047ef34587a145`,
    terminal `3437df6b3a3b8cc27284619199d6dfca751836f878fcba544de58f1ed0e9c4ba`,
    denied `4b7a3853b549d9434d78412dfa5a59b279e72159917b8c7311d870aff09b55f3`.
- RDD first found incomplete lifecycle scanning and a permissive login oracle;
  commit `2fecdcd` corrected both within 69 of 118 allowed lines. The cumulative
  candidate was then approved and consumed under
  `review-9aec4c2f9412f982`. Advisory `R3-1` notes that the four-second runtime
  expiry window could be sensitive on unusually slow runners; repeated local
  Terraform 1.10.5/1.11.4 runs were stable, and deterministic clock behavior is
  additionally covered by the PFF-003 unit suite.
