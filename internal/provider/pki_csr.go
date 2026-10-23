package provider

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Key types accepted by the GoVault sign route.
const (
	keyTypeECDSAP256 = "ecdsa-p256"
	keyTypeECDSAP384 = "ecdsa-p384"
	keyTypeRSA2048   = "rsa-2048"
	keyTypeRSA4096   = "rsa-4096"
)

var supportedKeyTypes = []string{keyTypeECDSAP256, keyTypeECDSAP384, keyTypeRSA2048, keyTypeRSA4096}

func isSupportedKeyType(keyType string) bool {
	for _, supported := range supportedKeyTypes {
		if keyType == supported {
			return true
		}
	}
	return false
}

// certificateNames are the identities a certificate request asks for.
type certificateNames struct {
	CommonName string
	DNS        []string
	IPs        []string
	URIs       []string
	Emails     []string
}

func (n certificateNames) empty() bool {
	return strings.TrimSpace(n.CommonName) == "" && len(n.DNS)+len(n.IPs)+len(n.URIs)+len(n.Emails) == 0
}

// generatePKIKey makes a new private key in this process. An empty type is the
// default, ecdsa-p256. The key is never sent anywhere.
func generatePKIKey(keyType string) (crypto.Signer, error) {
	switch keyType {
	case "", keyTypeECDSAP256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case keyTypeECDSAP384:
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case keyTypeRSA2048:
		return rsa.GenerateKey(rand.Reader, 2048)
	case keyTypeRSA4096:
		return rsa.GenerateKey(rand.Reader, 4096)
	}
	return nil, fmt.Errorf("unsupported key_type (use %s)", strings.Join(supportedKeyTypes, ", "))
}

// encodePKIKey renders a private key as PKCS#8 PEM.
func encodePKIKey(key crypto.Signer) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", errors.New("unable to encode the generated private key")
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

// buildCSR builds a signed certificate request with exactly the given names.
// The result holds the public key and the signature only.
func buildCSR(names certificateNames, key crypto.Signer) (string, error) {
	template := &x509.CertificateRequest{DNSNames: names.DNS, EmailAddresses: names.Emails}
	template.Subject.CommonName = strings.TrimSpace(names.CommonName)
	for _, text := range names.IPs {
		ip := net.ParseIP(strings.TrimSpace(text))
		if ip == nil {
			return "", errors.New("ip_sans must hold IP addresses")
		}
		template.IPAddresses = append(template.IPAddresses, ip)
	}
	for _, text := range names.URIs {
		uri, err := url.Parse(strings.TrimSpace(text))
		if err != nil || uri.Scheme == "" {
			return "", errors.New("uri_sans must hold URIs with a scheme")
		}
		template.URIs = append(template.URIs, uri)
	}
	for _, email := range names.Emails {
		if !strings.Contains(email, "@") {
			return "", errors.New("email_sans must hold e-mail addresses")
		}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return "", errors.New("unable to build the certificate request")
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), nil
}

// maxTTLDays is the longest lifetime the GoVault server signs.
const maxTTLDays = 397

var errTTLTooLong = errors.New("ttl must not exceed 397 days, the longest lifetime GoVault signs")

// parseTTLSeconds reads a lifetime such as 90m, 24h or 7d into whole seconds.
// An empty text is 0: the default of the role.
func parseTTLSeconds(text string) (int64, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return 0, nil
	}
	var duration time.Duration
	if days, ok := strings.CutSuffix(text, "d"); ok {
		n, err := strconv.ParseInt(days, 10, 64)
		if errors.Is(err, strconv.ErrRange) && !strings.HasPrefix(days, "-") {
			return 0, errTTLTooLong
		}
		if err != nil {
			return 0, errors.New("ttl must be a lifetime such as 90m, 24h or 7d")
		}
		if n > maxTTLDays {
			return 0, errTTLTooLong
		}
		duration = time.Duration(n) * 24 * time.Hour
	} else {
		parsed, err := time.ParseDuration(text)
		if err != nil {
			return 0, errors.New("ttl must be a lifetime such as 90m, 24h or 7d")
		}
		duration = parsed
	}
	if duration > maxTTLDays*24*time.Hour {
		return 0, errTTLTooLong
	}
	if duration <= 0 || duration%time.Second != 0 {
		return 0, errors.New("ttl must be a positive whole number of seconds")
	}
	return int64(duration / time.Second), nil
}

// certificateMatchingKey parses the first certificate of certPEM and refuses it
// unless its public key is the public half of key. Errors never repeat PEM.
func certificateMatchingKey(certPEM string, key crypto.Signer) (*x509.Certificate, error) {
	rest := []byte(certPEM)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, errors.New("GoVault returned no readable certificate")
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.New("GoVault returned a certificate that cannot be parsed")
		}
		equal, ok := cert.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
		if !ok || !equal.Equal(key.Public()) {
			return nil, errors.New("GoVault returned a certificate that is not for the generated key")
		}
		return cert, nil
	}
}
