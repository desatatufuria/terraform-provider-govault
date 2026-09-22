# Terraform Provider for GoVault

This repository contains the standalone Terraform provider for GoVault. It supports AppRole, product-neutral workload authentication, explicit token bootstrap, verified TLS configuration, and ephemeral secret reads.

## Requirements

- Terraform 1.10 or newer
- Go 1.25.8 or newer for provider development

The provider serves Terraform plugin protocol 6 at `registry.terraform.io/desatatufuria/govault`. The Terraform 1.10 product floor is intentionally stricter than protocol compatibility because GoVault secret reads will use Terraform ephemeral resources.

## AppRole authentication

Use AppRole for unattended runners that have a durable GoVault role but no
external identity provider. Supply both credentials through the process
environment before Terraform starts:

```shell
export GOVAULT_ROLE_ID="..."
export GOVAULT_SECRET_ID="..."
terraform plan
```

```hcl
terraform {
  required_version = ">= 1.10.0"

  required_providers {
    govault = {
      source = "desatatufuria/govault"
    }
  }
}

provider "govault" {
  address      = "https://govault.example.com"
  auth_method  = "approle"
  ca_cert_file = "/etc/govault/ca.pem"
}
```

Do not put RoleID or SecretID values in HCL. They are intentionally absent
from the provider schema and are read only from `GOVAULT_ROLE_ID` and
`GOVAULT_SECRET_ID`. For an AppRole outside the root namespace, add the
non-secret locator `approle_namespace = "team-a"`.

The AppRole is the durable machine identity. Each provider configuration
performs exactly one login and keeps the returned short-lived token only in
memory. The provider does **not** retry a failed or ambiguous AppRole login:
a limited-use SecretID may already have been consumed. Start a new Terraform
operation with a still-valid SecretID, or issue a replacement, instead of
expecting an automatic replay.

## Workload authentication

Use workload authentication when an external identity platform can issue an
assertion to the Terraform runner. Put that assertion in one explicitly named
environment variable; do not put it in Terraform configuration.

```hcl
terraform {
  required_version = ">= 1.10.0"

  required_providers {
    govault = {
      source = "desatatufuria/govault"
    }
  }
}

provider "govault" {
  address                = "https://govault.example.com"
  auth_method            = "workload"
  workload_role_ref      = "terraform-production"
  workload_assertion_env = "GOVAULT_WORKLOAD_ASSERTION"
  ca_cert_file           = "/etc/govault/ca.pem"
}
```

The runner must set `GOVAULT_WORKLOAD_ASSERTION` before Terraform starts. The
provider sends the assertion and `workload_role_ref` to
`POST /auth/workload/login`. GoVault chooses the namespace, policies, and
session lifetime from its server-side role; Terraform cannot override them.

The assertion is read on initial login and again only after the GoVault session
has expired. The resulting session token remains in provider memory. An
unexpected `401` is terminal: the provider does not exchange another assertion,
replay the secret request, fall back to token authentication, or try another
assertion source.

On Unix-like systems, a protected regular file is also supported:

```hcl
provider "govault" {
  address                 = "https://govault.example.com"
  auth_method             = "workload"
  workload_role_ref       = "terraform-production"
  workload_assertion_file = "/run/identity/govault.assertion"
}
```

The file must not be a symlink, must grant no permissions to group or other
users, and must be at most 262,144 bytes. Windows supports environment
assertions only. Configure exactly one of `workload_assertion_env` and
`workload_assertion_file`; there is no automatic source discovery or fallback.

## Token authentication

Use direct token authentication only when the runner already has a GoVault
token:

```hcl
provider "govault" {
  address      = "https://govault.example.com"
  auth_method  = "token"
  token_env    = "GOVAULT_TOKEN"
  ca_cert_file = "/etc/govault/ca.pem"
}
```

`token_env` names the only environment variable read for token bootstrap and
defaults to `GOVAULT_TOKEN` when omitted. There is deliberately no inline token
argument and no fallback to workload authentication or another environment
variable.

## TLS and authority

Provider configuration requires HTTPS, performs normal certificate and hostname
verification, and may add the PEM certificates selected by `ca_cert_file` to
the system trust roots. Requests use a 30-second timeout and honor Terraform
cancellation. Token authentication obtains its namespace from
`GET /auth/whoami`; workload and AppRole authentication obtain it from their
login responses. In AppRole mode, `approle_namespace` locates the role but the
response remains authoritative for the session namespace.

Authentication diagnostics contain stable error classes and HTTP status codes only. GoVault response bodies and token values are not copied into diagnostics.

## Ephemeral secrets

```hcl
ephemeral "govault_secret" "example" {
  path    = "infrastructure/example"
  version = 1 # optional; omit for latest
}
```

`value` and `resolved_version` are computed, sensitive, ephemeral results. The resource has no namespace, role, or policy selector, and the provider exposes no secret-bearing data source or managed resource.

Terraform acceptance uses explicitly supplied local binaries only: set `TF_ACC_TERRAFORM_1_10` and `TF_ACC_TERRAFORM_1_11`. Tests skip missing binaries and never download Terraform.

## Development

```shell
go test ./...
go test -race ./...
go vet ./...
go build ./...
```

## Publishing a release

Releases are built only from immutable SemVer tags by
`.github/workflows/release.yml`. The first release candidate is
`v0.1.0-rc.1`; consumers must pin it exactly until a stable version exists:

```hcl
terraform {
  required_providers {
    govault = {
      source  = "desatatufuria/govault"
      version = "= 0.1.0-rc.1"
    }
  }
}
```

### Signing prerequisites

Create a dedicated RSA GPG key for provider releases. Keep the private key and
its passphrase outside the repository, and publish only the public key. The
release workflow reads these repository secrets:

| GitHub secret | Value |
| --- | --- |
| `GPG_PRIVATE_KEY` | ASCII-armored private key exported for the dedicated release identity |
| `GPG_PASSPHRASE` | Passphrase for that private key |

`GITHUB_TOKEN` is supplied automatically by GitHub Actions; operators do not
create a repository secret with that name. The workflow imports the key only
inside the release job and passes its fingerprint to GoReleaser. Upload the
corresponding ASCII-armored **public** key when the provider is registered in
the Terraform Registry. Registry registration is a separate, explicitly
authorized operation and is not performed by this repository.

### Release procedure

1. Verify that the intended commit is on `main` and CI has passed.
2. Create one annotated immutable tag, for example `v0.1.0-rc.1`, at that exact
   commit.
3. Push only that tag after release publication has been authorized.
4. Confirm that the GitHub release contains the expected assets below.
5. Verify the checksum signature before registering or synchronizing the
   release with the Terraform Registry.

Never move or reuse a published tag, and never replace assets on an existing
release. Publish a new SemVer version for every correction.

For version `0.1.0-rc.1`, the release must contain:

- 11 platform ZIP archives named
  `terraform-provider-govault_0.1.0-rc.1_<os>_<arch>.zip`;
- `terraform-provider-govault_0.1.0-rc.1_SHA256SUMS`;
- detached signature
  `terraform-provider-govault_0.1.0-rc.1_SHA256SUMS.sig`;
- `terraform-provider-govault_0.1.0-rc.1_manifest.json` declaring protocol
  version `6.0`.

Each ZIP contains only the versioned provider executable. Verify the release
with the dedicated public key in an otherwise empty temporary keyring:

```shell
GNUPGHOME="$(mktemp -d)"
export GNUPGHOME
gpg --import terraform-provider-govault-release-public.asc
gpg --verify \
  terraform-provider-govault_0.1.0-rc.1_SHA256SUMS.sig \
  terraform-provider-govault_0.1.0-rc.1_SHA256SUMS
sha256sum --check terraform-provider-govault_0.1.0-rc.1_SHA256SUMS
rm -rf "${GNUPGHOME}"
unset GNUPGHOME
```

Run the checksum command in a directory containing every listed release asset.
Do not add the private signing key, exported secret values, `dist/`, or release
binaries to the repository.
