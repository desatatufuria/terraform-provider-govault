package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestLoginAppRoleUsesExactRootAndNamespacedContracts(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, namespace, path string
	}{
		{name: "root", path: "/auth/login"},
		{name: "namespaced", namespace: "team-a", path: "/ns/team-a/auth/login"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var loginRequests atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/ns/team-a/secrets/item" {
					if r.Header.Get("Authorization") != "Bearer session" {
						t.Errorf("authorization = %q", r.Header.Get("Authorization"))
					}
					_, _ = w.Write([]byte(`{"value":"secret","version":1}`))
					return
				}
				loginRequests.Add(1)
				if r.Method != http.MethodPost || r.URL.Path != test.path || r.Header.Get("Authorization") != "" {
					t.Errorf("request = %s %s authorization=%q", r.Method, r.URL.Path, r.Header.Get("Authorization"))
				}
				var body struct {
					Method      string            `json:"method"`
					Credentials map[string]string `json:"credentials"`
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Method != "approle" ||
					len(body.Credentials) != 2 || body.Credentials["role_id"] != "role-canary" || body.Credentials["secret_id"] != "secret-canary" {
					t.Errorf("body = %#v, error = %v", body, err)
				}
				_, _ = w.Write([]byte(`{"token":"session","access_token":"session","namespace":"team-a","created_at":1700000000,"expires_at":1700000010}`))
			}))
			defer server.Close()
			client := newTestProtocolClient(t, server, time.Second)
			client.now = func() time.Time { return time.Unix(1700000001, 0) }
			session, err := client.LoginAppRole(context.Background(), test.namespace, "role-canary", "secret-canary")
			if err != nil || session.Token != "session" || session.Namespace != "team-a" || session.CreatedAt.Unix() != 1700000000 || session.ExpiresAt.Unix() != 1700000010 {
				t.Fatalf("session = %#v, error = %v", session, err)
			}
			if loginRequests.Load() != 1 {
				t.Fatalf("login requests = %d, want 1", loginRequests.Load())
			}
			if err := client.InstallAppRoleSession(session); err != nil || client.Namespace() != "team-a" {
				t.Fatalf("install error = %v, namespace = %q", err, client.Namespace())
			}
			if _, err := client.ReadSecret(context.Background(), "demo", 0); err != nil {
				t.Fatalf("read with installed session: %v", err)
			}
		})
	}
}

func TestLoginAppRoleRejectsInvalidInputWithoutRequest(t *testing.T) {
	t.Parallel()
	var requests atomic.Int32
	client := &Client{baseURL: "https://govault.invalid", now: time.Now, httpClient: &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		requests.Add(1)
		return nil, errors.New("unexpected request")
	})}}
	for _, input := range []struct{ namespace, roleID, secretID string }{
		{roleID: "", secretID: "secret"},
		{roleID: "role", secretID: ""},
		{namespace: " \t", roleID: "role", secretID: "secret"},
		{roleID: " \n", secretID: "secret"},
		{roleID: "role", secretID: " \r"},
	} {
		if _, err := client.LoginAppRole(context.Background(), input.namespace, input.roleID, input.secretID); !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("error = %v", err)
		}
	}
	if requests.Load() != 0 {
		t.Fatalf("requests = %d, want 0", requests.Load())
	}
}

func TestLoginAppRoleAcceptsServerAheadClockSkew(t *testing.T) {
	t.Parallel()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"token":"session","access_token":"session","namespace":"team-a","created_at":103,"expires_at":200}`))
	}))
	defer server.Close()
	client := newTestProtocolClient(t, server, time.Second)
	client.now = func() time.Time { return time.Unix(100, 0) }
	session, err := client.LoginAppRole(context.Background(), "", "role", "secret")
	if err != nil {
		t.Fatalf("small server-ahead skew rejected: %v", err)
	}
	if err := client.InstallAppRoleSession(session); err != nil {
		t.Fatalf("install skewed session: %v", err)
	}
}

func TestLoginAppRoleClassifiesOneAttemptFailuresWithoutLeaks(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		status int
		want   error
	}{
		{"bad request", 400, ErrInvalidRequest},
		{"unauthorized", 401, ErrUnauthorized},
		{"forbidden", 403, ErrForbidden},
		{"rate limited", 429, ErrRateLimited},
		{"unavailable", 503, ErrServiceUnavailable},
		{"unexpected", 500, ErrUnexpectedStatus},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(`{"error":"role-canary secret-canary response-canary"}`))
			}))
			defer server.Close()
			_, err := newTestProtocolClient(t, server, time.Second).LoginAppRole(context.Background(), "", "role-canary", "secret-canary")
			if !errors.Is(err, test.want) || requests.Load() != 1 {
				t.Fatalf("error = %v, requests = %d, want %v and 1", err, requests.Load(), test.want)
			}
			assertAppRoleRedacted(t, err)
		})
	}
}

func TestLoginAppRoleRejectsInvalidSuccessResponses(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"malformed":             `{`,
		"trailing":              `{"token":"x","access_token":"x","namespace":"n","created_at":1,"expires_at":3}{}`,
		"missing token":         `{"access_token":"x","namespace":"n","created_at":1,"expires_at":3}`,
		"aliases differ":        `{"token":"x","access_token":"y","namespace":"n","created_at":1,"expires_at":3}`,
		"namespace empty":       `{"token":"x","access_token":"x","namespace":"","created_at":1,"expires_at":3}`,
		"creation missing":      `{"token":"x","access_token":"x","namespace":"n","expires_at":3}`,
		"creation after expiry": `{"token":"x","access_token":"x","namespace":"n","created_at":4,"expires_at":3}`,
		"expiry before issue":   `{"token":"x","access_token":"x","namespace":"n","created_at":1,"expires_at":1}`,
		"expired":               `{"token":"x","access_token":"x","namespace":"n","created_at":1,"expires_at":2}`,
		"oversized":             `{"token":"response-canary","pad":"` + strings.Repeat("x", maxWorkloadLoginBody) + `"}`,
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				_, _ = w.Write([]byte(body))
			}))
			defer server.Close()
			client := newTestProtocolClient(t, server, time.Second)
			client.now = func() time.Time { return time.Unix(2, 0) }
			_, err := client.LoginAppRole(context.Background(), "", "role-canary", "secret-canary")
			if !errors.Is(err, ErrInvalidResponse) || requests.Load() != 1 {
				t.Fatalf("error = %v, requests = %d", err, requests.Load())
			}
			assertAppRoleRedacted(t, err)
		})
	}
}

func TestLoginAppRoleTransportFailureIsOneAttemptAndRedacted(t *testing.T) {
	t.Parallel()
	var requests atomic.Int32
	client := &Client{baseURL: "https://govault.invalid", now: time.Now, httpClient: &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		requests.Add(1)
		return nil, errors.New("role-canary secret-canary transport-canary")
	})}}
	_, err := client.LoginAppRole(context.Background(), "team-a", "role-canary", "secret-canary")
	if !errors.Is(err, ErrRequestFailed) || requests.Load() != 1 {
		t.Fatalf("error = %v, requests = %d", err, requests.Load())
	}
	assertAppRoleRedacted(t, err)
}

func assertAppRoleRedacted(t *testing.T, err error) {
	t.Helper()
	for _, canary := range []string{"role-canary", "secret-canary", "response-canary", "transport-canary"} {
		if strings.Contains(err.Error(), canary) {
			t.Fatalf("error leaked %q: %v", canary, err)
		}
	}
}
