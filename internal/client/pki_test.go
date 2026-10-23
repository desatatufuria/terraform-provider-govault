package client

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testCertPEM  = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
	testSignBody = `{"id":"gv.pki.cert.1","certificate_pem":"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n","issuing_ca_pem":"ica","ca_chain_pem":"chain","serial_number":"1a2b","not_after":1767312000,"issuer_ca_id":"gv.pki.ca.1","issuer_serial":"9f"}`
)

func authenticatedTestClient(t *testing.T, server *httptest.Server) *Client {
	t.Helper()
	client := newTestClient(t, server, server.URL, "gv.token-canary", time.Second)
	if err := client.InstallWorkloadSession(WorkloadSession{Token: "gv.token-canary", Namespace: "team-a", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatalf("install session: %v", err)
	}
	return client
}

func TestSignCSRSendsOnlyTheRequestAndParsesTheCertificate(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		if r.Method != http.MethodPost || r.URL.Path != "/ns/team-b/pki/sign/web" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer gv.token-canary" || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("headers = %v", r.Header)
		}
		got := string(body)
		for _, want := range []string{`"csr_pem":"csr-text"`, `"common_name":"api.example.test"`, `"ttl_seconds":3600`} {
			if !strings.Contains(got, want) {
				t.Errorf("body %s lacks %s", got, want)
			}
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(testSignBody))
	}))
	defer server.Close()

	signed, err := authenticatedTestClient(t, server).SignCSR(context.Background(), "team-b", "web", SignRequest{CSRPEM: "csr-text", CommonName: "api.example.test", TTLSeconds: 3600})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if signed.CertificatePEM != testCertPEM || signed.SerialNumber != "1a2b" || signed.NotAfter != 1767312000 || signed.CAChainPEM != "chain" || signed.IssuingCAPEM != "ica" || signed.ID != "gv.pki.cert.1" {
		t.Fatalf("signed = %#v", signed)
	}
	if calls.Load() != 1 {
		t.Fatalf("calls = %d", calls.Load())
	}
}

func TestSignCSRDefaultsToSessionNamespaceAndOmitsEmptyFields(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.URL.Path != "/ns/team-a/pki/sign/mesh" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if strings.Contains(string(body), "common_name") || strings.Contains(string(body), "ttl_seconds") {
			t.Errorf("empty fields were sent: %s", body)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(testSignBody))
	}))
	defer server.Close()

	if _, err := authenticatedTestClient(t, server).SignCSR(context.Background(), "", "mesh", SignRequest{CSRPEM: "csr"}); err != nil {
		t.Fatalf("sign: %v", err)
	}
}

func TestSignCSRRejectsInvalidInputBeforeAnyRequest(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer server.Close()
	client := authenticatedTestClient(t, server)
	for name, test := range map[string]struct {
		namespace, role string
		request         SignRequest
	}{
		"empty role":      {"team-a", " ", SignRequest{CSRPEM: "csr"}},
		"empty csr":       {"team-a", "web", SignRequest{}},
		"negative ttl":    {"team-a", "web", SignRequest{CSRPEM: "csr", TTLSeconds: -1}},
		"bad namespace":   {"Team/A", "web", SignRequest{CSRPEM: "csr"}},
		"private key csr": {"team-a", "web", SignRequest{CSRPEM: "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"}},
	} {
		if _, err := client.SignCSR(context.Background(), test.namespace, test.role, test.request); !errors.Is(err, ErrInvalidConfiguration) {
			t.Errorf("%s: error = %v", name, err)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("requests sent = %d", calls.Load())
	}
}

func TestSignCSRWithoutSessionFails(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("unexpected request") }))
	defer server.Close()
	client := newTestClient(t, server, server.URL, "gv.token-canary", time.Second)
	if _, err := client.SignCSR(context.Background(), "", "web", SignRequest{CSRPEM: "csr"}); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("error = %v", err)
	}
}

// A sign call issues a certificate every time, so no status, transport failure
// or timeout may ever cause a second request.
func TestSignCSRNeverRetries(t *testing.T) {
	t.Parallel()

	for _, status := range []int{400, 401, 403, 404, 409, 429, 500, 502, 503} {
		var calls atomic.Int32
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"error":"secret-canary -----BEGIN PRIVATE KEY----- gv.token-canary"}`))
		}))
		_, err := authenticatedTestClient(t, server).SignCSR(context.Background(), "team-a", "web", SignRequest{CSRPEM: "csr"})
		server.Close()
		if err == nil {
			t.Fatalf("status %d: expected error", status)
		}
		if calls.Load() != 1 {
			t.Errorf("status %d: calls = %d, want exactly 1", status, calls.Load())
		}
		for _, leak := range []string{"secret-canary", "PRIVATE KEY", "gv.token-canary"} {
			if strings.Contains(err.Error(), leak) {
				t.Errorf("status %d: error leaks %q: %v", status, leak, err)
			}
		}
	}
}

func TestSignCSRMapsStatusClasses(t *testing.T) {
	t.Parallel()

	for status, want := range map[int]error{401: ErrUnauthorized, 403: ErrForbidden, 400: ErrInvalidRequest, 404: ErrInvalidRequest, 409: ErrInvalidRequest, 429: ErrRateLimited, 503: ErrServiceUnavailable, 500: ErrUnexpectedStatus} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) }))
		_, err := authenticatedTestClient(t, server).SignCSR(context.Background(), "team-a", "web", SignRequest{CSRPEM: "csr"})
		server.Close()
		if !errors.Is(err, want) {
			t.Errorf("status %d: error = %v, want %v", status, err, want)
		}
	}
}

func TestSignCSRRejectsRedirectWithoutForwardingToken(t *testing.T) {
	t.Parallel()

	var redirected atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected.Add(1) }))
	defer target.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	if _, err := authenticatedTestClient(t, server).SignCSR(context.Background(), "team-a", "web", SignRequest{CSRPEM: "csr"}); err == nil {
		t.Fatal("redirect must fail")
	}
	if redirected.Load() != 0 {
		t.Fatal("redirect target was contacted")
	}
}

func TestSignCSRRejectsMalformedAnswers(t *testing.T) {
	t.Parallel()

	for name, body := range map[string]string{
		"not json":         `nope`,
		"no certificate":   `{"serial_number":"1","not_after":1}`,
		"no serial":        `{"certificate_pem":"x","not_after":1}`,
		"no expiry":        `{"certificate_pem":"x","serial_number":"1"}`,
		"trailing data":    testSignBody + `{}`,
		"private key echo": `{"certificate_pem":"x","serial_number":"1","not_after":1,"private_key_pem":"k"}`,
	} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(body))
		}))
		_, err := authenticatedTestClient(t, server).SignCSR(context.Background(), "team-a", "web", SignRequest{CSRPEM: "csr"})
		server.Close()
		if !errors.Is(err, ErrInvalidResponse) {
			t.Errorf("%s: error = %v", name, err)
		}
	}
}

func TestSignCSRTimeoutIsNotRetried(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	release := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls.Add(1)
		<-release
	}))
	defer server.Close()
	defer close(release)
	client := newTestClient(t, server, server.URL, "gv.token-canary", 100*time.Millisecond)
	if err := client.InstallWorkloadSession(WorkloadSession{Token: "gv.token-canary", Namespace: "team-a", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.SignCSR(context.Background(), "team-a", "web", SignRequest{CSRPEM: "csr"}); err == nil {
		t.Fatal("timeout must fail")
	}
	if calls.Load() != 1 {
		t.Fatalf("calls = %d", calls.Load())
	}
}

func TestPublicCABundleNeedsNoCredentials(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/pki/public/team-a/ca-bundle.pem" || r.Method != http.MethodGet {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "" {
			t.Error("public route received credentials")
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write([]byte(testCertPEM + testCertPEM))
	}))
	defer server.Close()
	// A protocol client with no session at all can still read the public bundle.
	client := newTestClient(t, server, server.URL, "gv.token-canary", time.Second)
	bundle, err := client.PublicCABundle(context.Background(), "team-a")
	if err != nil || bundle != testCertPEM+testCertPEM {
		t.Fatalf("bundle = %q, %v", bundle, err)
	}
}

func TestPublicCABundleUsesSessionNamespaceWhenOmitted(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/pki/public/team-a/ca-bundle.pem" {
			t.Errorf("path = %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(testCertPEM))
	}))
	defer server.Close()
	if _, err := authenticatedTestClient(t, server).PublicCABundle(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	other := newTestClient(t, server, server.URL, "gv.token-canary", time.Second)
	if _, err := other.PublicCABundle(context.Background(), ""); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("no namespace anywhere: %v", err)
	}
}

func TestPublicCABundleRejectsBadAnswers(t *testing.T) {
	t.Parallel()

	for name, test := range map[string]struct {
		status int
		body   string
		want   error
	}{
		"not found":      {404, `{"error":"x"}`, ErrInvalidRequest},
		"rate limited":   {429, ``, ErrRateLimited},
		"unavailable":    {503, ``, ErrServiceUnavailable},
		"no certificate": {200, `hello`, ErrInvalidResponse},
		"key in bundle":  {200, testCertPEM + "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n", ErrInvalidResponse},
		"empty":          {200, ``, ErrInvalidResponse},
	} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(test.status)
			_, _ = w.Write([]byte(test.body))
		}))
		_, err := authenticatedTestClient(t, server).PublicCABundle(context.Background(), "team-a")
		server.Close()
		if !errors.Is(err, test.want) {
			t.Errorf("%s: error = %v, want %v", name, err, test.want)
		}
	}
}

func TestPublicIssuerCertificateConvertsDERToPEM(t *testing.T) {
	t.Parallel()

	block, _ := pem.Decode([]byte(testCertPEM))
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/pki/public/team-a/gv.pki.ca.1/ca.der" {
			t.Errorf("path = %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/pkix-cert")
		_, _ = w.Write(block.Bytes)
	}))
	defer server.Close()
	got, err := authenticatedTestClient(t, server).PublicIssuerCertificate(context.Background(), "team-a", "gv.pki.ca.1")
	if err != nil || got != testCertPEM {
		t.Fatalf("issuer = %q, %v", got, err)
	}
	if _, err := authenticatedTestClient(t, server).PublicIssuerCertificate(context.Background(), "team-a", "../x"); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("bad issuer: %v", err)
	}
}

func refusalServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	return server
}

func TestSignCSRShowsTheRefusalMessageForTheThreeRefusalStatuses(t *testing.T) {
	t.Parallel()

	for _, status := range []int{400, 409, 422} {
		server := refusalServer(t, status, `{"error":"common name not allowed by the role"}`)
		_, err := authenticatedTestClient(t, server).SignCSR(context.Background(), "team-a", "web", SignRequest{CSRPEM: "csr"})
		want := fmt.Sprintf("HTTP %d: common name not allowed by the role", status)
		if !errors.Is(err, ErrInvalidRequest) || err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("status %d: error = %v, want %q", status, err, want)
		}
	}
}

func TestPublicReadShowsTheRefusalMessageToo(t *testing.T) {
	t.Parallel()

	server := refusalServer(t, 409, `{"error":"no active issuer"}`)
	_, err := authenticatedTestClient(t, server).PublicCABundle(context.Background(), "team-a")
	if err == nil || !strings.Contains(err.Error(), "HTTP 409: no active issuer") {
		t.Fatalf("error = %v", err)
	}
}

func TestRefusalMessageIsSanitised(t *testing.T) {
	t.Parallel()

	long := strings.Repeat("é", 150) // 300 bytes
	cases := map[string]struct {
		body string
		want string // exact error suffix after the status class; "" means no message
	}{
		"control characters":   {`{"error":"bad\u0000 name\r\n\u001b[31mred\u007f"}`, "bad name[31mred"},
		"capped at 200 bytes":  {`{"error":"` + long + `"}`, strings.Repeat("é", 100)},
		"pem is dropped":       {`{"error":"refused -----BEGIN PRIVATE KEY----- abc"}`, ""},
		"split pem is dropped": {`{"error":"-----BE\u0000GIN PRIVATE KEY-----"}`, ""},
		"lower case pem":       {`{"error":"-----begin certificate-----"}`, ""},
		"zero width in pem":    {`{"error":"-----BEG\u200bIN PRIVATE KEY-----"}`, ""},
		"joiner in pem":        {`{"error":"x -----BEGIN\u200d CERTIFICATE-----"}`, ""},
		"bidi override":        {`{"error":"name \u202egnp.exe\u202c \u2066x\u2069"}`, "name gnp.exe x"},
		"byte order mark":      {`{"error":"\ufeffrefused"}`, "refused"},
		"clean message":        {`{"error":"role web is not allowed"}`, "role web is not allowed"},
		"cap after stripping":  {`{"error":"` + strings.Repeat("é\u200b", 150) + `"}`, strings.Repeat("é", 100)},
		"not json":             {`oops`, ""},
		"no error field":       {`{"detail":"x"}`, ""},
		"empty error":          {`{"error":"  "}`, ""},
	}
	for name, tc := range cases {
		server := refusalServer(t, 400, tc.body)
		_, err := authenticatedTestClient(t, server).SignCSR(context.Background(), "team-a", "web", SignRequest{CSRPEM: "csr"})
		want := "GoVault rejected the request: HTTP 400"
		if tc.want != "" {
			want += ": " + tc.want
		}
		if err == nil || err.Error() != want {
			t.Errorf("%s: error = %q, want %q", name, err, want)
		}
		if err != nil && (strings.Contains(err.Error(), "BEGIN") || len(err.Error()) > len(want)) {
			t.Errorf("%s: unsafe error %q", name, err)
		}
	}
}

func TestOtherStatusesNeverRepeatTheBody(t *testing.T) {
	t.Parallel()

	for _, status := range []int{401, 403, 404, 429, 500, 503} {
		server := refusalServer(t, status, `{"error":"secret-detail"}`)
		_, err := authenticatedTestClient(t, server).SignCSR(context.Background(), "team-a", "web", SignRequest{CSRPEM: "csr"})
		if err == nil || strings.Contains(err.Error(), "secret-detail") {
			t.Errorf("status %d: error = %v", status, err)
		}
	}
}
