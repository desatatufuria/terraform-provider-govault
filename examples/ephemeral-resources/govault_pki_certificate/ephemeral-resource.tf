# The private key is generated inside the provider process and never sent to
# GoVault; only a certificate request is. Each run issues a new certificate.
ephemeral "govault_pki_certificate" "api" {
  namespace   = "team-a"
  role        = "web"
  common_name = "api.example.test"
  alt_names   = ["api.example.test"]
  ttl         = "24h"
  key_type    = "ecdsa-p256"
}

# On a self-issue profile role send no names; GoVault builds the subject from
# the authenticated identity.
ephemeral "govault_pki_certificate" "mesh" {
  role = "mesh"
  self = true
}

# WARNING: private_key must only flow into write-only or ephemeral-capable
# destinations (a write-only attribute, a provider block, a local-exec
# environment). Any ordinary attribute would store the key in the Terraform
# state and plan. Requires Terraform 1.11+ and a provider whose resource
# supports write-only attributes; check its documentation.
resource "kubernetes_secret_v1" "api_tls" {
  metadata {
    name      = "api-tls"
    namespace = "default"
  }
  type = "kubernetes.io/tls"

  data_wo = {
    "tls.crt" = ephemeral.govault_pki_certificate.api.certificate
    "tls.key" = ephemeral.govault_pki_certificate.api.private_key
  }
  # Bump to write a newly issued certificate; write-only values are not diffed.
  data_wo_revision = 1
}
