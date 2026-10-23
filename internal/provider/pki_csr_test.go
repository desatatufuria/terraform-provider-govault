package provider

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestGeneratePKIKeyTypes(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		keyType string
		check   func(any) bool
	}{
		{"", func(k any) bool { key, ok := k.(*ecdsa.PrivateKey); return ok && key.Curve == elliptic.P256() }},
		{"ecdsa-p256", func(k any) bool { key, ok := k.(*ecdsa.PrivateKey); return ok && key.Curve == elliptic.P256() }},
		{"ecdsa-p384", func(k any) bool { key, ok := k.(*ecdsa.PrivateKey); return ok && key.Curve == elliptic.P384() }},
		{"rsa-2048", func(k any) bool { key, ok := k.(*rsa.PrivateKey); return ok && key.N.BitLen() == 2048 }},
	} {
		key, err := generatePKIKey(test.keyType)
		if err != nil || !test.check(key) {
			t.Errorf("%q: key = %T, err = %v", test.keyType, key, err)
		}
	}
	if _, err := generatePKIKey("rsa-1024"); err == nil {
		t.Error("unsupported key type must fail")
	}
	if !isSupportedKeyType("rsa-4096") || isSupportedKeyType("dsa") {
		t.Error("key type list is wrong")
	}
}

func TestEncodePKIKeyIsPKCS8AndRoundTrips(t *testing.T) {
	t.Parallel()

	key, _ := generatePKIKey("ecdsa-p256")
	encoded, err := encodePKIKey(key)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(encoded))
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatalf("block = %#v", block)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil || !key.Public().(*ecdsa.PublicKey).Equal(parsed.(*ecdsa.PrivateKey).Public()) {
		t.Fatalf("round trip failed: %v", err)
	}
}

func TestBuildCSRCarriesNamesAndOnlyThePublicKey(t *testing.T) {
	t.Parallel()

	key, _ := generatePKIKey("ecdsa-p256")
	csrPEM, err := buildCSR(certificateNames{
		CommonName: "api.example.test", DNS: []string{"api.example.test", "www.example.test"},
		IPs: []string{"10.0.0.1"}, URIs: []string{"spiffe://example.test/api"}, Emails: []string{"ops@example.test"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(csrPEM, "PRIVATE KEY") {
		t.Fatal("CSR PEM contains a private key block")
	}
	block, rest := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(strings.TrimSpace(string(rest))) != 0 {
		t.Fatalf("PEM is not exactly one certificate request: %#v", block)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		t.Fatalf("csr: %v", err)
	}
	if csr.Subject.CommonName != "api.example.test" || len(csr.DNSNames) != 2 || len(csr.IPAddresses) != 1 || len(csr.URIs) != 1 || len(csr.EmailAddresses) != 1 {
		t.Fatalf("csr names = %#v", csr)
	}
	if !csr.PublicKey.(*ecdsa.PublicKey).Equal(key.Public()) {
		t.Fatal("CSR public key is not the generated key")
	}
}

func TestBuildCSRWithoutNamesForSelfIssue(t *testing.T) {
	t.Parallel()

	key, _ := generatePKIKey("ecdsa-p256")
	csrPEM, err := buildCSR(certificateNames{}, key)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(csrPEM))
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.Subject.CommonName != "" || len(csr.DNSNames)+len(csr.IPAddresses)+len(csr.URIs)+len(csr.EmailAddresses) != 0 {
		t.Fatalf("self-issue CSR must carry no names: %#v, %v", csr, err)
	}
}

func TestBuildCSRRejectsMalformedNames(t *testing.T) {
	t.Parallel()

	key, _ := generatePKIKey("ecdsa-p256")
	for name, names := range map[string]certificateNames{
		"bad ip":    {CommonName: "a", IPs: []string{"not-an-ip"}},
		"bad uri":   {CommonName: "a", URIs: []string{"no-scheme"}},
		"bad email": {CommonName: "a", Emails: []string{"nobody"}},
	} {
		if _, err := buildCSR(names, key); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestParseTTLSeconds(t *testing.T) {
	t.Parallel()

	for text, want := range map[string]int64{"": 0, "90m": 5400, "24h": 86400, "7d": 604800, "30s": 30} {
		if got, err := parseTTLSeconds(text); err != nil || got != want {
			t.Errorf("%q = %d, %v; want %d", text, got, err, want)
		}
	}
	for _, text := range []string{"abc", "-1h", "0s", "1.5s", "xd", "1h30"} {
		if _, err := parseTTLSeconds(text); err == nil {
			t.Errorf("%q must fail", text)
		}
	}
}

func TestParseTTLSecondsBoundsTheLifetimeToTheServerCeiling(t *testing.T) {
	t.Parallel()

	for text, want := range map[string]int64{"397d": 397 * 86400, "9528h": 397 * 86400, "1d": 86400} {
		if got, err := parseTTLSeconds(text); err != nil || got != want {
			t.Errorf("%q = %d, %v; want %d", text, got, err, want)
		}
	}
	for _, text := range []string{"398d", "106751d", "106752d", "200000d", "99999999999d", "9529h", "2147483647d"} {
		_, err := parseTTLSeconds(text)
		if err == nil || !strings.Contains(err.Error(), "397 days") {
			t.Errorf("%q must fail naming the 397 day limit, got %v", text, err)
		}
	}
}

func signedFor(t *testing.T, public any, notBefore, notAfter time.Time) string {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "leaf"}, NotBefore: notBefore, NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestCertificateMatchesKey(t *testing.T) {
	t.Parallel()

	key, _ := generatePKIKey("ecdsa-p256")
	other, _ := generatePKIKey("ecdsa-p256")
	now := time.Now()
	good := signedFor(t, key.Public(), now, now.Add(time.Hour))
	cert, err := certificateMatchingKey(good, key)
	if err != nil || cert.SerialNumber.Int64() != 7 {
		t.Fatalf("matching certificate refused: %v", err)
	}
	if _, err := certificateMatchingKey(good, other); err == nil || strings.Contains(err.Error(), "BEGIN") {
		t.Fatalf("certificate for another key must be refused without PEM in the error: %v", err)
	}
	if _, err := certificateMatchingKey("junk", key); err == nil {
		t.Fatal("garbage must be refused")
	}
}
