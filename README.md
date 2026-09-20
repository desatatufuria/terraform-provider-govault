# Terraform Provider for GoVault

This repository contains the standalone Terraform provider for GoVault. It supports bounded token bootstrap and verified TLS configuration. Secret resources are not exposed yet.

## Requirements

- Terraform 1.10 or newer
- Go 1.25 or newer for provider development

The provider serves Terraform plugin protocol 6 at `registry.terraform.io/desatatufuria/govault`. The Terraform 1.10 product floor is intentionally stricter than protocol compatibility because GoVault secret reads will use Terraform ephemeral resources.

## Configuration

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
  address     = "https://govault.example.com"
  auth_method = "token"
  token_env   = "GOVAULT_TOKEN"
}
```

`token_env` names the only environment variable read for token bootstrap and defaults to `GOVAULT_TOKEN` when omitted. There is deliberately no inline token argument or fallback to another environment variable.

Provider configuration requires HTTPS, performs normal certificate and hostname verification, and may add the PEM certificates selected by `ca_cert_file` to the system trust roots. Requests use a 30-second timeout and honor Terraform cancellation. During configuration the provider calls `GET /auth/whoami` with bearer authentication and retains the namespace returned by GoVault for future ephemeral operations; the namespace is not user-selectable.

Authentication diagnostics contain stable error classes and HTTP status codes only. GoVault response bodies and token values are not copied into diagnostics.

## Development

```shell
go test ./...
go test -race ./...
go vet ./...
go build ./...
```
