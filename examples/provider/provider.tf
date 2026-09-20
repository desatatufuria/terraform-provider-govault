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
  auth_method  = "token"
  token_env    = "GOVAULT_TOKEN"
  ca_cert_file = "/etc/govault/ca.pem"
}
