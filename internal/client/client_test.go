package client

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestAuthenticateUsesBearerTokenAndDerivesNamespace(t *testing.T) {
	t.Parallel()

	const token = "gv.test-token"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != whoAmIPath {
			t.Errorf("request = %s %s, want GET %s", r.Method, r.URL.Path, whoAmIPath)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+token {
			t.Errorf("authorization header = %q", got)
		}
		if got := r.Header.Get("Accept"); got != "application/json" {
			t.Errorf("accept header = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"namespace":"team-a"}`))
	}))
	defer server.Close()

	client := newTestClient(t, server, server.URL, token, time.Second)
	if err := client.Authenticate(context.Background()); err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if got := client.Namespace(); got != "team-a" {
		t.Fatalf("namespace = %q, want team-a", got)
	}
}

func TestAuthenticateTLSVerification(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"namespace":"team-a"}`))
	}))
	defer server.Close()

	t.Run("untrusted CA fails closed", func(t *testing.T) {
		client, err := New(Config{Address: server.URL, Token: "gv.token", Timeout: time.Second})
		if err != nil {
			t.Fatalf("new client: %v", err)
		}
		if err := client.Authenticate(context.Background()); !errors.Is(err, ErrRequestFailed) {
			t.Fatalf("error = %v, want request failure", err)
		}
	})

	t.Run("explicit CA is trusted", func(t *testing.T) {
		client := newTestClient(t, server, server.URL, "gv.token", time.Second)
		if err := client.Authenticate(context.Background()); err != nil {
			t.Fatalf("authenticate: %v", err)
		}
	})

	t.Run("hostname mismatch fails", func(t *testing.T) {
		parsed, err := url.Parse(server.URL)
		if err != nil {
			t.Fatal(err)
		}
		parsed.Host = "localhost:" + parsed.Port()
		client := newTestClient(t, server, parsed.String(), "gv.token", time.Second)
		if err := client.Authenticate(context.Background()); !errors.Is(err, ErrRequestFailed) {
			t.Fatalf("error = %v, want request failure", err)
		}
	})
}

func TestAuthenticateHonorsTimeoutAndCancellation(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()

	t.Run("client timeout", func(t *testing.T) {
		client := newTestClient(t, server, server.URL, "gv.token", 20*time.Millisecond)
		err := client.Authenticate(context.Background())
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("error = %v, want deadline exceeded", err)
		}
	})

	t.Run("caller cancellation", func(t *testing.T) {
		client := newTestClient(t, server, server.URL, "gv.token", time.Second)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err := client.Authenticate(ctx)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want context canceled", err)
		}
	})
}

func TestAuthenticateRedactsSensitiveFailures(t *testing.T) {
	t.Parallel()

	const (
		token  = "gv.redaction-canary"
		secret = "response-secret-canary"
	)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(token + " " + secret))
	}))
	defer server.Close()

	client := newTestClient(t, server, server.URL, token, time.Second)
	err := client.Authenticate(context.Background())
	if !errors.Is(err, ErrUnexpectedStatus) {
		t.Fatalf("error = %v, want unexpected status", err)
	}
	assertRedacted(t, err, token, secret)

	client.httpClient.Transport = roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("transport failure " + token + " " + secret)
	})
	err = client.Authenticate(context.Background())
	if !errors.Is(err, ErrRequestFailed) {
		t.Fatalf("error = %v, want request failure", err)
	}
	assertRedacted(t, err, token, secret)
}

func TestAuthenticateRejectsRedirectWithoutForwardingToken(t *testing.T) {
	t.Parallel()

	var redirectedRequests atomic.Int32
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirectedRequests.Add(1)
	}))
	defer redirectTarget.Close()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirectTarget.URL, http.StatusFound)
	}))
	defer server.Close()

	client := newTestClient(t, server, server.URL, "gv.redirect-canary", time.Second)
	if err := client.Authenticate(context.Background()); !errors.Is(err, ErrUnexpectedStatus) {
		t.Fatalf("error = %v, want unexpected status", err)
	}
	if got := redirectedRequests.Load(); got != 0 {
		t.Fatalf("redirect target received %d requests, want 0", got)
	}
}

func TestCloneVerifiedTransportIgnoresAmbientUnsafeTLS(t *testing.T) {
	t.Parallel()

	ambient := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} // Deliberately unsafe negative control.
	transport := cloneVerifiedTransport(ambient)
	if transport.TLSClientConfig == ambient.TLSClientConfig {
		t.Fatal("TLS configuration must not alias the ambient transport")
	}
	if transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("client inherited ambient InsecureSkipVerify")
	}
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("minimum TLS version = %d, want TLS 1.2", transport.TLSClientConfig.MinVersion)
	}
}

func TestAuthenticateClassifiesServerFailures(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		status int
		body   string
		want   error
	}{
		"unauthorized":      {status: http.StatusUnauthorized, body: `{"error":"denied"}`, want: ErrUnauthorized},
		"forbidden":         {status: http.StatusForbidden, body: `{"error":"denied"}`, want: ErrForbidden},
		"invalid JSON":      {status: http.StatusOK, body: `{`, want: ErrInvalidResponse},
		"missing namespace": {status: http.StatusOK, body: `{}`, want: ErrInvalidResponse},
		"trailing JSON":     {status: http.StatusOK, body: `{"namespace":"team-a"}{}`, want: ErrInvalidResponse},
		"trailing content":  {status: http.StatusOK, body: `{"namespace":"team-a"}secret`, want: ErrInvalidResponse},
		"oversized body":    {status: http.StatusOK, body: `{"namespace":"team-a"}` + strings.Repeat(" ", maxWhoAmIBody), want: ErrInvalidResponse},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()

			client := newTestClient(t, server, server.URL, "gv.token", time.Second)
			if err := client.Authenticate(context.Background()); !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestNewRejectsUnsafeConfiguration(t *testing.T) {
	t.Parallel()

	tests := map[string]Config{
		"plaintext address": {Address: "http://govault.example.com", Token: "gv.token"},
		"missing host":      {Address: "https://", Token: "gv.token"},
		"empty token":       {Address: "https://govault.example.com", Token: ""},
		"malformed token":   {Address: "https://govault.example.com", Token: "gv. token"},
		"invalid CA":        {Address: "https://govault.example.com", Token: "gv.token", CACertFile: filepath.Join(t.TempDir(), "missing.pem")},
	}
	for name, config := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := New(config); !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("error = %v, want invalid configuration", err)
			}
		})
	}
}

func newTestClient(t *testing.T, server *httptest.Server, address, token string, timeout time.Duration) *Client {
	t.Helper()
	certificate := server.Certificate()
	if certificate == nil {
		t.Fatal("test server has no certificate")
	}
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	if err := os.WriteFile(caFile, pemData, 0o600); err != nil {
		t.Fatalf("write CA: %v", err)
	}
	client, err := New(Config{Address: address, Token: token, CACertFile: caFile, Timeout: timeout})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	return client
}

func assertRedacted(t *testing.T, err error, values ...string) {
	t.Helper()
	for _, value := range values {
		if strings.Contains(err.Error(), value) {
			t.Fatalf("error leaked %q: %v", value, err)
		}
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}
