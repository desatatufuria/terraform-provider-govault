# PKI certificates for the Terraform provider (GoVault PKI scope B, P2.3)

## Status

- Feature: implementation complete, not pushed
- Branch: `feat/pki-certificates`, from `origin/main` `5ab783f` (AppRole merged)
- Delivery strategy: `single-pr` (push, PR and merge are the owner's decision)
- Forecast and actual: about 2,000 authored lines in four work units, almost
  half of them tests; the heuristic of 400 lines per task is exceeded by the
  test-heavy units and kept as is (tests and docs travel with behaviour).
- Effective TDD: tests written first; RED was a compile failure for each unit
  (undefined symbols), then GREEN.

## Objective

Let Terraform obtain a GoVault PKI certificate whose private key is generated
locally and never leaves the provider process, without any of it entering plan
or state, and read the public CA bundle of a namespace.

## Authorized scope

- Ephemeral resource `govault_pki_certificate`.
- Data source `govault_pki_bundle` (public data).
- Reuse the existing client and authentication (token, workload, AppRole).
- Docs, examples, README, fake-server acceptance case.

## Constraints

- No legacy or compatibility layers (pre-launch).
- Never log, print or put in an error: a key, token or PEM.
- A sign call is never retried: every accepted call issues a certificate.
- No remote host, no GitHub, no registry publish, no `gentle-ai review`.

## Verified contracts (GoVault server, read-only)

- `POST /ns/{namespace}/pki/sign/{role}`; body `csr_pem` (required),
  `common_name`, `ttl_seconds`; answer `201` with `id`, `certificate_pem`,
  `issuing_ca_pem`, `ca_chain_pem`, `serial_number`, `not_after`,
  `issuer_ca_id`, `issuer_serial`; never a private key.
- Accepted keys: RSA 2048/4096, ECDSA P-256/P-384. A CSR with a private key
  block is refused (`400`). Names (DNS, IP, URI, e-mail) travel inside the CSR.
- Self-issue profile role (`bind_identity`): the server builds the subject;
  `common_name` must not be sent (`400`).
- Public routes, no token: `GET /pki/public/{namespace}/ca-bundle.pem`,
  `GET /pki/public/{namespace}/{issuer}/ca.der`. The authenticated
  `/pki/ca-bundle` has no issuer parameter.

## Decisions

- **Bundle route: the public one.** It needs no policy, the provider already
  has a verified HTTPS client, and only the public route can return one issuer
  (as DER, converted to PEM). The data source receives a narrowed reader
  (`publicBundleClient`), never the client that holds the session, because data
  sources land in state.
- **No `Renew`.** Framework v1.19.0 supports ephemeral renewal, but a result
  cannot change after `Open`, so renewing could not hand a new certificate to
  its consumers. Each open issues a new certificate; renewal is a follow-up.
- **Retry policy: none.** One HTTP request, no retry on any status, transport
  error or timeout, redirects refused, `GetBody` unset. A timeout can still
  have issued a certificate; the answer carries `id` to revoke it.
- **Errors carry the status class only** (like the secret resource), never the
  server body. Detailed refusal text is a possible follow-up with sanitising.
- **Key handling:** generated in process (`ecdsa-p256` default, `ecdsa-p384`,
  `rsa-2048`, `rsa-4096`), PKCS#8 PEM output marked `Sensitive`; the returned
  certificate must match the generated key or nothing is returned. Go cannot
  zero key material, so the key lives until garbage collection.
- **`self`** with any name is refused at validate time (known values) and again
  at open time; without `self`, `common_name` is required (as in the CLI).
- **Namespace** is optional and defaults to the session namespace; it is
  validated as a GoVault namespace name before any request.

## Tasks

- [x] **PKC-001 — Client sign call, public reads, CSR helper**
  - Route: inline writer (single bounded writer task).
  - Evidence: `SignCSR`, `PublicCABundle`, `PublicIssuerCertificate`; CSR,
    key, TTL and key/certificate match helpers. RED: `go vet` undefined symbols
    in both packages; GREEN: `go test ./internal/client` and focused provider
    tests. Covers no-retry for 9 statuses, timeout, redirect, redaction,
    malformed and key-echoing answers.
  - Work-unit commit: `14b8c4a` (full hash in `git log`).
- [x] **PKC-002 — Ephemeral resource `govault_pki_certificate`**
  - Evidence: schema, `ValidateConfig`, `Open`, local key, only the CSR sent
    (httptest asserts no `PRIVATE KEY` and no key material in the body),
    certificate/key match, 6 error statuses surfaced without secrets and not
    retried, `self` conflicts, key types, workload session signs after login.
  - Work-unit commit: `4f215e0`.
- [x] **PKC-003 — Data source `govault_pki_bundle`**
  - Evidence: namespace and issuer reads, no credentials on the wire,
    redaction, provider sharing only the public reader with data sources
    (existing PHE-002 and AppRole guard tests updated to say so).
  - Work-unit commit: `fad0d44`.
- [x] **PKC-004 — Docs, examples, README, acceptance**
  - Evidence: docs generated offline with
    `GOPROXY=file:///go/pkg/mod/cache/download GOSUMDB=off go generate ./...`
    (existing `secret.md` and `index.md` unchanged); README section with the
    write-only warning; Kubernetes `data_wo` example; fake-server acceptance
    case `runTerraformPKIAcceptance` (skips without the pinned binaries).
  - Work-unit commit: `669b392`.
- [x] **PKC-005 — Follow-up unit: F208, F206, D-C (owner decision)**
  - F208 `6815335`, `b9444b7`: `parseTTLSeconds` bounded to 397 days (days and
    total duration; the error names the limit); RED: `398d`, `106751d`,
    `9529h` accepted, `200000d`/`99999999999d` failed with unrelated messages;
    GREEN with `398d`, `106751d`, `106752d`, `200000d`, `99999999999d`,
    `2147483647d`, `9529h` refused and `397d`, `9528h`, `1d` accepted.
  - F206 `45e9b74`: workload session public reads log in only when the
    namespace is omitted (one login shared by repeated reads, none with an
    explicit namespace); the data source still receives only the narrowed
    public reader. RED: read failed with `invalid GoVault client configuration`.
  - D-C `cead7bd`: for 400, 409 and 422 the client keeps the server `error`
    text (control characters stripped, 200 bytes at most, dropped if it holds
    `-----BEGIN` in any case or split by control characters), as
    `HTTP <status>: <message>`; 422 now maps to the invalid-request class;
    sign is still never retried and other statuses never repeat the body. RED
    shown with the old client (messages absent, 422 unexpected status).
- [x] **PKC-006 — F207 acceptance consumer and direct lifecycle test** `f03750e`
  - The acceptance case adds `ephemeral "govault_secret" "consumer"` whose path
    is the certificate serial, so Terraform must open the certificate; it
    asserts 1 sign and 1 consumer read after plan, still 1 after show, 2 after
    apply, 2 after state pull, and scans every surface for PRIVATE KEY /
    BEGIN EC / BEGIN RSA. Skips without the pinned binaries; nothing was run.
  - New Go test `TestPKICertificateEphemeralLifecycleKeepsTheKeyLocal` drives
    Configure/Open/Close with the real client against the fake server: one sign
    per open, distinct keys, key sensitive, matches the certificate, never sent.

## Verification

- `go build ./...`, `go vet ./...`, `gofmt -l .`, `git diff --check`: clean.
- `go test ./... -count=1`: passed. `go test -race ./internal/... -count=1`:
  passed.
- Skipped: `TestTerraformEphemeralAcceptance` (no `TF_ACC_TERRAFORM_1_10` /
  `_1_11` binaries here), so the new Terraform-level case did not run.

- Follow-up unit: `go build`, `go vet`, `gofmt -l`, `go test ./... -count=1`
  passed; only `TestTerraformEphemeralAcceptance` skipped. Offline
  `go generate ./...` ran and changed no docs beyond the ttl description.

- Follow-up F265/F266/F267 (commits 65d0375, 55fd70e): refusal messages also
  lose `unicode.Cf` characters before the PEM check; the acceptance fake issues
  a distinct serial per sign call and asserts each consumer read names the
  serial issued by its open; the lifecycle test checks the PEM block and the key
  type. `go build`, `go vet`, `gofmt -l`, `go test ./... -count=1` passed;
  `TestTerraformEphemeralAcceptance` still skipped.

## Unverified

- Real GoVault and real Terraform runs; the Kubernetes `data_wo` example was
  not applied and depends on the kubernetes provider version in use.
- The acceptance case now consumes the ephemeral certificate (see PKC-006) and
  asserts sign counts, but it has still never run: no Terraform binaries here
  and none were downloaded (not authorised). Whether Terraform evaluates the
  consumer exactly once per plan and once per apply is therefore unproved.
- Not scanned: TF_LOG output of the PKI acceptance case (no TRACE log there).

## Follow-ups

- (Done in PKC-005, D-C.) Sanitised surfacing of the server refusal text.
- Ephemeral renewal if Terraform ever allows a changed result.
- (Done in PKC-006, F207.) A consumer in the acceptance case.
- (Done, F265/F266/F267.) Serial per sign call, format-character stripping, checked assertions.
