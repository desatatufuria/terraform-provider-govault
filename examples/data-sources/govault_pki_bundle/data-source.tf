# Public CA certificates of a namespace (intermediate and root).
data "govault_pki_bundle" "team_a" {
  namespace = "team-a"
}

# Public certificate of one intermediate CA.
data "govault_pki_bundle" "issuer" {
  namespace = "team-a"
  issuer    = "gv.pki.ca.0000000000000001"
}
