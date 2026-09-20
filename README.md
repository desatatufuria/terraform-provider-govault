# Terraform Provider for GoVault

This repository contains the standalone Terraform provider for GoVault. It supports product-neutral workload authentication, explicit token bootstrap, verified TLS configuration, and ephemeral secret reads.

## Requirements

- Terraform 1.10 or newer
- Go 1.25 or newer for provider development

The provider serves Terraform plugin protocol 6 at `registry.terraform.io/desatatufuria/govault`. The Terraform 1.10 product floor is intentionally stricter than protocol compatibility because GoVault secret reads will use Terraform ephemeral resources.

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
`GET /auth/whoami`; workload authentication obtains it from the login response.
In both modes, the namespace is server-authoritative and is not user-selectable.

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
