package client

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestLoginWorkloadUsesExactContract(t *testing.T) {
	t.Parallel()
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != workloadLoginPath || r.Header.Get("Authorization") != "" {
			t.Errorf("request = %s %s authorization=%q", r.Method, r.URL.Path, r.Header.Get("Authorization"))
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body) != 2 || body["role_ref"] != "role-a" || body["assertion"] != "assertion-a" {
			t.Errorf("body = %#v, error = %v", body, err)
		}
		_, _ = w.Write([]byte(`{"token":"session","access_token":"session","namespace":"team-a","expires_at":1700000010,"additive":true}`))
	}))
	defer server.Close()
	client := newTestProtocolClient(t, server, time.Second)
	client.now = func() time.Time { return time.Unix(1700000000, 0) }
	session, err := client.LoginWorkload(context.Background(), "role-a", "assertion-a")
	if err != nil || session.Token != "session" || session.Namespace != "team-a" || session.ExpiresAt.Unix() != 1700000010 {
		t.Fatalf("session = %#v, error = %v", session, err)
	}
	if requests.Load() != 1 {
		t.Fatalf("requests = %d, want 1", requests.Load())
	}
}

func TestLoginWorkloadClassifiesOneAttemptFailures(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, body, retryAfter string
		status                 int
		want                   error
	}{
		{"bad request", `{"code":"invalid_request"}`, "", 400, ErrInvalidRequest},
		{"unauthorized", `{"code":"unauthenticated","error":"response-canary"}`, "", 401, ErrUnauthorized},
		{"rate limited", `{"code":"rate_limited"}`, "17", 429, ErrRateLimited},
		{"unavailable", `{"code":"service_unavailable"}`, "", 503, ErrServiceUnavailable},
		{"code disagreement", `{"code":"unauthenticated"}`, "", 400, ErrInvalidResponse},
		{"malformed", `{`, "", 401, ErrInvalidResponse},
		{"trailing", `{"code":"unauthenticated"}{}`, "", 401, ErrInvalidResponse},
		{"retry zero", `{"code":"rate_limited"}`, "0", 429, ErrInvalidResponse},
		{"retry overflow", `{"code":"rate_limited"}`, "18446744073709551616", 429, ErrInvalidResponse},
		{"unexpected status", `response-canary`, "", 500, ErrUnexpectedStatus},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				if test.retryAfter != "" {
					w.Header().Set("Retry-After", test.retryAfter)
				}
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			_, err := newTestProtocolClient(t, server, time.Second).LoginWorkload(context.Background(), "role", "assertion")
			if !errors.Is(err, test.want) || requests.Load() != 1 {
				t.Fatalf("error = %v, requests = %d, want %v and 1", err, requests.Load(), test.want)
			}
			if strings.Contains(err.Error(), "response-canary") {
				t.Fatalf("error leaked response body: %v", err)
			}
			if test.status == 429 && test.want == ErrRateLimited {
				var failure *WorkloadLoginError
				if !errors.As(err, &failure) || !failure.HasRetryAfter || failure.RetryAfterSeconds != 17 {
					t.Fatalf("rate-limit metadata = %#v", failure)
				}
			}
		})
	}
}

func TestLoginWorkloadRejectsInvalidSuccessResponses(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"malformed":       `{`,
		"trailing":        `{"token":"x","access_token":"x","namespace":"n","expires_at":2}{}`,
		"aliases differ":  `{"token":"x","access_token":"y","namespace":"n","expires_at":2}`,
		"namespace empty": `{"token":"x","access_token":"x","namespace":"","expires_at":2}`,
		"expired":         `{"token":"x","access_token":"x","namespace":"n","expires_at":1}`,
		"oversized":       `{"token":"x","access_token":"x","namespace":"n","expires_at":2,"pad":"` + strings.Repeat("x", maxWorkloadLoginBody) + `"}`,
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { requests.Add(1); _, _ = w.Write([]byte(body)) }))
			defer server.Close()
			client := newTestProtocolClient(t, server, time.Second)
			client.now = func() time.Time { return time.Unix(1, 0) }
			if _, err := client.LoginWorkload(context.Background(), "role", "assertion"); !errors.Is(err, ErrInvalidResponse) || requests.Load() != 1 {
				t.Fatalf("error = %v, requests = %d", err, requests.Load())
			}
		})
	}
}

func TestLoginWorkloadTransportIsBounded(t *testing.T) {
	t.Parallel()
	var initial, redirected atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected.Add(1) }))
	defer target.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		initial.Add(1)
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer server.Close()
	client := newTestProtocolClient(t, server, time.Second)
	if _, err := client.LoginWorkload(context.Background(), "role", "assertion"); !errors.Is(err, ErrUnexpectedStatus) {
		t.Fatalf("redirect error = %v", err)
	}
	if initial.Load() != 1 || redirected.Load() != 0 {
		t.Fatalf("redirect requests = initial %d, target %d", initial.Load(), redirected.Load())
	}
	untrusted, err := NewProtocolClient(Config{Address: server.URL, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	baseTransport, tlsAttempts := untrusted.httpClient.Transport, atomic.Int32{}
	untrusted.httpClient.Transport = roundTripperFunc(func(r *http.Request) (*http.Response, error) { tlsAttempts.Add(1); return baseTransport.RoundTrip(r) })
	if _, err := untrusted.LoginWorkload(context.Background(), "role", "assertion"); !errors.Is(err, ErrRequestFailed) || tlsAttempts.Load() != 1 {
		t.Fatalf("TLS error = %v, attempts = %d", err, tlsAttempts.Load())
	}
	for name, transportErr := range map[string]error{"timeout": context.DeadlineExceeded, "cancel": context.Canceled, "TLS": errors.New("TLS canary")} {
		t.Run(name, func(t *testing.T) {
			var requests atomic.Int32
			client.httpClient.Transport = roundTripperFunc(func(*http.Request) (*http.Response, error) { requests.Add(1); return nil, transportErr })
			_, err := client.LoginWorkload(context.Background(), "role", "assertion")
			if requests.Load() != 1 || (!errors.Is(err, transportErr) && !errors.Is(err, ErrRequestFailed)) || strings.Contains(err.Error(), "TLS canary") {
				t.Fatalf("error = %v, requests = %d", err, requests.Load())
			}
		})
	}
}

func TestLoginWorkloadPreservesBodyReadCancellation(t *testing.T) {
	client := &Client{baseURL: "https://govault.invalid", now: time.Now, httpClient: &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(errorReader{context.DeadlineExceeded}), Header: make(http.Header)}, nil
	})}}
	_, err := client.LoginWorkload(context.Background(), "role", "assertion")
	if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("body-read error = %v", err)
	}
}

type errorReader struct{ err error }

func (r errorReader) Read([]byte) (int, error) { return 0, r.err }

func TestLoginWorkloadRejectsInvalidInputWithoutRequest(t *testing.T) {
	t.Parallel()
	var requests atomic.Int32
	client := &Client{
		baseURL: "https://govault.invalid",
		now:     time.Now,
		httpClient: &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			requests.Add(1)
			return nil, errors.New("unexpected request")
		})},
	}
	for _, input := range []struct{ role, assertion string }{{"", "a"}, {"r", ""}, {strings.Repeat("r", 129), "a"}, {"r", strings.Repeat("a", maxWorkloadAssertionBytes+1)}, {"r", string([]byte{0xff})}} {
		if _, err := client.LoginWorkload(context.Background(), input.role, input.assertion); !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("error = %v", err)
		}
	}
	if requests.Load() != 0 {
		t.Fatalf("requests = %d, want 0", requests.Load())
	}
}

func TestWorkloadContractFixtureHash(t *testing.T) {
	data, err := os.ReadFile("testdata/workload-login-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		SchemaVersion int             `json:"schema_version"`
		Provenance    string          `json:"govault_provenance"`
		Hash          string          `json:"content_sha256"`
		Contract      json.RawMessage `json:"contract"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(fixture.Contract)
	if fixture.SchemaVersion != 1 || fixture.Provenance == "" || hex.EncodeToString(sum[:]) != fixture.Hash {
		t.Fatalf("invalid workload contract fixture metadata")
	}
}

func newTestProtocolClient(t *testing.T, server *httptest.Server, timeout time.Duration) *Client {
	t.Helper()
	certificate := server.Certificate()
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if certificate == nil || os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}), 0o600) != nil {
		t.Fatal("prepare test CA")
	}
	client, err := NewProtocolClient(Config{Address: server.URL, CACertFile: caFile, Timeout: timeout})
	if err != nil {
		t.Fatalf("new protocol client: %v", err)
	}
	return client
}
