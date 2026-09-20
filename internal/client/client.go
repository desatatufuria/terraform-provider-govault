package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	DefaultTimeout            = 30 * time.Second
	whoAmIPath                = "/auth/whoami"
	maxWhoAmIBody             = 1 << 20
	maxSecretBody             = 7 << 20
	workloadLoginPath         = "/auth/workload/login"
	maxWorkloadAssertionBytes = 262144
	maxWorkloadLoginBody      = 1 << 20
	maxRetryAfterBytes        = 20
)

var (
	ErrInvalidConfiguration = errors.New("invalid GoVault client configuration")
	ErrUnauthorized         = errors.New("GoVault authentication rejected")
	ErrForbidden            = errors.New("GoVault access forbidden")
	ErrRequestFailed        = errors.New("GoVault request failed")
	ErrUnexpectedStatus     = errors.New("GoVault returned an unexpected status")
	ErrInvalidResponse      = errors.New("GoVault returned an invalid response")
	ErrInvalidRequest       = errors.New("GoVault rejected the request")
	ErrRateLimited          = errors.New("GoVault rate limited the request")
	ErrServiceUnavailable   = errors.New("GoVault service unavailable")
)

type Config struct {
	Address    string
	Token      string
	CACertFile string
	Timeout    time.Duration
}

type Client struct {
	baseURL    string
	token      string
	httpClient *http.Client
	now        func() time.Time

	mu        sync.RWMutex
	namespace string
}

// WorkloadSession is the short-lived session returned by workload login.
type WorkloadSession struct {
	Token     string
	Namespace string
	ExpiresAt time.Time
}

// WorkloadLoginError contains only stable, non-sensitive protocol metadata.
type WorkloadLoginError struct {
	StatusCode        int
	Code              string
	RetryAfterSeconds uint64
	HasRetryAfter     bool
	cause             error
}

func (e *WorkloadLoginError) Error() string { return e.cause.Error() }
func (e *WorkloadLoginError) Unwrap() error { return e.cause }

type whoAmIResponse struct {
	Namespace string `json:"namespace"`
}

type Secret struct {
	Value   string `json:"value"`
	Version int64  `json:"version"`
}

func New(config Config) (*Client, error) {
	if strings.TrimSpace(config.Token) == "" || strings.IndexFunc(config.Token, unicode.IsSpace) >= 0 {
		return nil, fmt.Errorf("%w: token is empty or malformed", ErrInvalidConfiguration)
	}
	return newProtocolClient(config)
}

// NewProtocolClient constructs the verified HTTP boundary without requiring a
// static token. Authentication methods remain explicit operations on Client.
func NewProtocolClient(config Config) (*Client, error) {
	if config.Token != "" {
		return nil, fmt.Errorf("%w: protocol client cannot accept a static token", ErrInvalidConfiguration)
	}
	return newProtocolClient(config)
}

func newProtocolClient(config Config) (*Client, error) {
	baseURL, err := normalizeAddress(config.Address)
	if err != nil {
		return nil, err
	}

	defaultTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("%w: default HTTP transport is unavailable", ErrInvalidConfiguration)
	}
	transport := cloneVerifiedTransport(defaultTransport)
	tlsConfig := transport.TLSClientConfig
	if config.CACertFile != "" {
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		pemData, err := os.ReadFile(config.CACertFile)
		if err != nil {
			return nil, fmt.Errorf("%w: unable to read CA certificate file", ErrInvalidConfiguration)
		}
		if !roots.AppendCertsFromPEM(pemData) {
			return nil, fmt.Errorf("%w: CA certificate file contains no certificates", ErrInvalidConfiguration)
		}
		tlsConfig.RootCAs = roots
	}
	transport.TLSClientConfig = tlsConfig

	timeout := config.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	return &Client{
		baseURL: baseURL,
		token:   config.Token,
		now:     time.Now,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// LoginWorkload exchanges one external assertion for one GoVault session.
// It performs exactly one HTTP request and never retries or follows redirects.
func (c *Client) LoginWorkload(ctx context.Context, roleRef, assertion string) (WorkloadSession, error) {
	if strings.Trim(roleRef, " \t\n\r\v\f") == "" || len(roleRef) > 128 ||
		strings.Trim(assertion, " \t\n\r\v\f") == "" || len(assertion) > maxWorkloadAssertionBytes || !utf8.ValidString(assertion) {
		return WorkloadSession{}, ErrInvalidConfiguration
	}
	body, err := json.Marshal(struct {
		RoleRef   string `json:"role_ref"`
		Assertion string `json:"assertion"`
	}{roleRef, assertion})
	if err != nil {
		return WorkloadSession{}, ErrRequestFailed
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+workloadLoginPath, bytes.NewReader(body))
	if err != nil {
		return WorkloadSession{}, ErrRequestFailed
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	response, err := c.httpClient.Do(request)
	if err != nil {
		return WorkloadSession{}, sanitizedRequestError(err)
	}
	defer response.Body.Close()

	payload, err := readBoundedBody(response.Body, maxWorkloadLoginBody)
	if err != nil {
		return WorkloadSession{}, ErrInvalidResponse
	}
	if response.StatusCode != http.StatusOK {
		return WorkloadSession{}, workloadLoginFailure(response, payload)
	}
	var result struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
		Namespace   string `json:"namespace"`
		ExpiresAt   int64  `json:"expires_at"`
	}
	if decodeOneJSON(payload, &result) != nil || result.Token == "" || result.Token != result.AccessToken ||
		strings.TrimSpace(result.Namespace) == "" || result.ExpiresAt <= c.now().Unix() {
		return WorkloadSession{}, ErrInvalidResponse
	}
	return WorkloadSession{Token: result.Token, Namespace: result.Namespace, ExpiresAt: time.Unix(result.ExpiresAt, 0)}, nil
}

func workloadLoginFailure(response *http.Response, body []byte) error {
	want := map[int]struct {
		code string
		err  error
	}{
		http.StatusBadRequest:         {"invalid_request", ErrInvalidRequest},
		http.StatusUnauthorized:       {"unauthenticated", ErrUnauthorized},
		http.StatusTooManyRequests:    {"rate_limited", ErrRateLimited},
		http.StatusServiceUnavailable: {"service_unavailable", ErrServiceUnavailable},
	}
	expected, ok := want[response.StatusCode]
	if !ok {
		return fmt.Errorf("%w: HTTP %d", ErrUnexpectedStatus, response.StatusCode)
	}
	var payload struct {
		Code string `json:"code"`
	}
	if decodeOneJSON(body, &payload) != nil || payload.Code != expected.code {
		return ErrInvalidResponse
	}
	failure := &WorkloadLoginError{StatusCode: response.StatusCode, Code: payload.Code, cause: expected.err}
	if response.StatusCode == http.StatusTooManyRequests {
		value := response.Header.Get("Retry-After")
		if value != "" {
			if len(value) > maxRetryAfterBytes || strings.IndexFunc(value, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
				return ErrInvalidResponse
			}
			seconds, err := strconv.ParseUint(value, 10, 64)
			if err != nil || seconds == 0 {
				return ErrInvalidResponse
			}
			failure.RetryAfterSeconds, failure.HasRetryAfter = seconds, true
		}
	}
	return failure
}

func readBoundedBody(body io.Reader, limit int64) ([]byte, error) {
	payload, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil || int64(len(payload)) > limit {
		return nil, ErrInvalidResponse
	}
	return payload, nil
}

func decodeOneJSON(body []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrInvalidResponse
	}
	return nil
}

func (c *Client) Authenticate(ctx context.Context) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+whoAmIPath, nil)
	if err != nil {
		return ErrRequestFailed
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	request.Header.Set("Accept", "application/json")

	response, err := c.httpClient.Do(request)
	if err != nil {
		return sanitizedRequestError(err)
	}
	defer response.Body.Close()

	switch response.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized:
		return ErrUnauthorized
	case http.StatusForbidden:
		return ErrForbidden
	default:
		return fmt.Errorf("%w: HTTP %d", ErrUnexpectedStatus, response.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, maxWhoAmIBody+1))
	if err != nil || len(body) > maxWhoAmIBody {
		return ErrInvalidResponse
	}
	var payload whoAmIResponse
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(&payload); err != nil {
		return ErrInvalidResponse
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrInvalidResponse
	}
	payload.Namespace = strings.TrimSpace(payload.Namespace)
	if payload.Namespace == "" {
		return ErrInvalidResponse
	}

	c.mu.Lock()
	c.namespace = payload.Namespace
	c.mu.Unlock()
	return nil
}

func cloneVerifiedTransport(base *http.Transport) *http.Transport {
	transport := base.Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return transport
}

func (c *Client) Namespace() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.namespace
}

func (c *Client) ReadSecret(ctx context.Context, path string, version int64) (Secret, error) {
	namespace := c.Namespace()
	if namespace == "" || strings.TrimSpace(path) == "" || version < 0 {
		return Secret{}, ErrInvalidConfiguration
	}
	query := url.Values{"name": []string{path}}
	if version > 0 {
		query.Set("version", fmt.Sprint(version))
	}
	requestURL := c.baseURL + "/ns/" + url.PathEscape(namespace) + "/secrets/item?" + query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return Secret{}, ErrRequestFailed
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	request.Header.Set("Accept", "application/json")
	response, err := c.httpClient.Do(request)
	if err != nil {
		return Secret{}, sanitizedRequestError(err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusUnauthorized {
		return Secret{}, ErrUnauthorized
	}
	if response.StatusCode == http.StatusForbidden {
		return Secret{}, ErrForbidden
	}
	if response.StatusCode != http.StatusOK {
		return Secret{}, fmt.Errorf("%w: HTTP %d", ErrUnexpectedStatus, response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxSecretBody+1))
	if err != nil || len(body) > maxSecretBody {
		return Secret{}, ErrInvalidResponse
	}
	var secret Secret
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(&secret); err != nil || secret.Value == "" || secret.Version <= 0 {
		return Secret{}, ErrInvalidResponse
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Secret{}, ErrInvalidResponse
	}
	return secret, nil
}

func normalizeAddress(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("%w: address must be an absolute HTTPS URL", ErrInvalidConfiguration)
	}
	return strings.TrimRight(parsed.String(), "/"), nil
}

func sanitizedRequestError(err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return fmt.Errorf("GoVault request canceled: %w", context.Canceled)
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("GoVault request timed out: %w", context.DeadlineExceeded)
	default:
		return ErrRequestFailed
	}
}
