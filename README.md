# Terraform Provider for GoVault

This repository contains the standalone Terraform provider for GoVault. The current bootstrap exposes only offline provider configuration; it does not read tokens, make network requests, or expose secret resources yet.

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

`token_env` names the environment variable that a later implementation phase will read; it is not token material. There is deliberately no inline token argument. `ca_cert_file` may select a custom PEM CA file, but this scaffold does not read it yet.

## Development

```shell
go test ./...
go test -race ./...
go vet ./...
go build ./...
```
