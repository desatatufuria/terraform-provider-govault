package client

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maxPKIBody = 1 << 20
	pemPrivate = "PRIVATE KEY"
)

var (
	pkiNamespacePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	pkiIssuerPattern    = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
)

// SignRequest is the body of the PKI sign route. Only a certificate request
// (public key plus names) leaves the process; the private key never does.
type SignRequest struct {
	CSRPEM     string `json:"csr_pem"`
	CommonName string `json:"common_name,omitempty"`
	TTLSeconds int64  `json:"ttl_seconds,omitempty"`
}

// SignedCertificate is the public answer of the PKI sign route.
type SignedCertificate struct {
	ID             string `json:"id"`
	CertificatePEM string `json:"certificate_pem"`
	IssuingCAPEM   string `json:"issuing_ca_pem"`
	CAChainPEM     string `json:"ca_chain_pem"`
	SerialNumber   string `json:"serial_number"`
	NotAfter       int64  `json:"not_after"`
	IssuerCAID     string `json:"issuer_ca_id"`
	IssuerSerial   string `json:"issuer_serial"`
}

// SignCSR asks GoVault to sign a certificate request under a PKI role.
//
// It performs exactly one HTTP request and NEVER retries, not on a transport
// error, a timeout or any status: every accepted call issues and records a new
// certificate, so a blind replay would issue a second one. Redirects are not
// followed. An empty namespace selects the namespace of the session. Failures
// carry the HTTP status class and, for 400, 409 and 422, the sanitised refusal
// message; never any other part of the answer body.
func (c *Client) SignCSR(ctx context.Context, namespace, role string, request SignRequest) (SignedCertificate, error) {
	c.mu.RLock()
	token, sessionNamespace := c.token, c.namespace
	c.mu.RUnlock()
	if namespace == "" {
		namespace = sessionNamespace
	}
	role = strings.TrimSpace(role)
	if token == "" || !pkiNamespacePattern.MatchString(namespace) || role == "" || strings.TrimSpace(request.CSRPEM) == "" ||
		request.TTLSeconds < 0 || strings.Contains(request.CSRPEM, pemPrivate) {
		return SignedCertificate{}, ErrInvalidConfiguration
	}
	body, err := json.Marshal(request)
	if err != nil {
		return SignedCertificate{}, ErrRequestFailed
	}
	requestURL := c.baseURL + "/ns/" + url.PathEscape(namespace) + "/pki/sign/" + url.PathEscape(role)
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL, bytes.NewReader(body))
	if err != nil {
		return SignedCertificate{}, ErrRequestFailed
	}
	// Without GetBody the transport can never replay the request on its own.
	httpRequest.GetBody = nil
	httpRequest.Header.Set("Authorization", "Bearer "+token)
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Accept", "application/json")
	response, err := c.httpClient.Do(httpRequest)
	if err != nil {
		return SignedCertificate{}, sanitizedRequestError(err)
	}
	defer response.Body.Close()
	if err := pkiStatusError(response, http.StatusCreated); err != nil {
		return SignedCertificate{}, err
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxPKIBody+1))
	if err != nil || len(raw) > maxPKIBody {
		return SignedCertificate{}, ErrInvalidResponse
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var signed SignedCertificate
	if err := decoder.Decode(&signed); err != nil || signed.CertificatePEM == "" || signed.SerialNumber == "" || signed.NotAfter <= 0 {
		return SignedCertificate{}, ErrInvalidResponse
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return SignedCertificate{}, ErrInvalidResponse
	}
	// The sign route never knows a private key; refuse an answer that carries one.
	var echoed struct {
		PrivateKeyPEM json.RawMessage `json:"private_key_pem"`
	}
	if err := json.Unmarshal(raw, &echoed); err != nil || echoed.PrivateKeyPEM != nil {
		return SignedCertificate{}, ErrInvalidResponse
	}
	return signed, nil
}

// PublicCABundle reads the public CA bundle (intermediate and root, PEM) of a
// namespace. The route is unauthenticated: no credential is sent. An empty
// namespace selects the namespace of the session, if there is one.
func (c *Client) PublicCABundle(ctx context.Context, namespace string) (string, error) {
	namespace, err := c.publicNamespace(namespace)
	if err != nil {
		return "", err
	}
	raw, err := c.publicGet(ctx, "/pki/public/"+url.PathEscape(namespace)+"/ca-bundle.pem", "application/x-pem-file")
	if err != nil {
		return "", err
	}
	if !onlyCertificates(raw) {
		return "", ErrInvalidResponse
	}
	return string(raw), nil
}

// PublicIssuerCertificate reads the public certificate of one intermediate CA
// (DER on the wire) and returns it PEM encoded.
func (c *Client) PublicIssuerCertificate(ctx context.Context, namespace, issuer string) (string, error) {
	namespace, err := c.publicNamespace(namespace)
	if err != nil {
		return "", err
	}
	if !pkiIssuerPattern.MatchString(issuer) {
		return "", ErrInvalidConfiguration
	}
	raw, err := c.publicGet(ctx, "/pki/public/"+url.PathEscape(namespace)+"/"+url.PathEscape(issuer)+"/ca.der", "application/pkix-cert")
	if err != nil {
		return "", err
	}
	if len(raw) == 0 || bytes.Contains(raw, []byte("-----BEGIN")) {
		return "", ErrInvalidResponse
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})), nil
}

func (c *Client) publicNamespace(namespace string) (string, error) {
	if namespace == "" {
		namespace = c.Namespace()
	}
	if !pkiNamespacePattern.MatchString(namespace) {
		return "", ErrInvalidConfiguration
	}
	return namespace, nil
}

// publicGet performs one credential-free GET and returns the bounded body.
func (c *Client) publicGet(ctx context.Context, path, accept string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, ErrRequestFailed
	}
	request.Header.Set("Accept", accept)
	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, sanitizedRequestError(err)
	}
	defer response.Body.Close()
	if err := pkiStatusError(response, http.StatusOK); err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxPKIBody+1))
	if err != nil || len(raw) > maxPKIBody {
		return nil, ErrInvalidResponse
	}
	return raw, nil
}

// maxRefusalBody bounds how much of a refusal body is read for its message.
const maxRefusalBody = 4 << 10

// maxRefusalMessage caps the server message shown to the operator.
const maxRefusalMessage = 200

// pkiStatusError maps a status to a stable error. For 400, 409 and 422 it adds
// the server's fixed refusal message after sanitising it; no other status and
// no other body content is ever repeated.
func pkiStatusError(response *http.Response, success int) error {
	status := response.StatusCode
	switch status {
	case success:
		return nil
	case http.StatusUnauthorized:
		return ErrUnauthorized
	case http.StatusForbidden:
		return ErrForbidden
	case http.StatusBadRequest, http.StatusConflict, http.StatusUnprocessableEntity:
		if message := refusalMessage(response.Body); message != "" {
			return fmt.Errorf("%w: HTTP %d: %s", ErrInvalidRequest, status, message)
		}
		return fmt.Errorf("%w: HTTP %d", ErrInvalidRequest, status)
	case http.StatusNotFound:
		return fmt.Errorf("%w: HTTP %d", ErrInvalidRequest, status)
	case http.StatusTooManyRequests:
		return ErrRateLimited
	case http.StatusServiceUnavailable:
		return ErrServiceUnavailable
	}
	return fmt.Errorf("%w: HTTP %d", ErrUnexpectedStatus, status)
}

// refusalMessage returns the "error" text of a refusal body, or "" when there is
// none or it is unsafe to show. Control characters are removed, a message that
// looks like PEM is dropped whole, and the result is capped at 200 bytes.
func refusalMessage(body io.Reader) string {
	raw, err := io.ReadAll(io.LimitReader(body, maxRefusalBody))
	if err != nil {
		return ""
	}
	var payload struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(raw, &payload) != nil {
		return ""
	}
	text := payload.Error
	if strings.Contains(strings.ToUpper(text), "-----BEGIN") || !utf8.ValidString(text) {
		return ""
	}
	text = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, text)
	text = strings.TrimSpace(text)
	if strings.Contains(strings.ToUpper(text), "-----BEGIN") {
		return ""
	}
	for len(text) > maxRefusalMessage {
		_, size := utf8.DecodeLastRuneInString(text)
		text = text[:len(text)-size]
	}
	return strings.TrimSpace(text)
}

// onlyCertificates reports whether data is one or more CERTIFICATE PEM blocks
// and nothing else.
func onlyCertificates(data []byte) bool {
	count := 0
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			return count > 0 && len(bytes.TrimSpace(data)) == 0
		}
		if block.Type != "CERTIFICATE" {
			return false
		}
		count++
		data = rest
	}
}
