package provider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	govaultclient "github.com/desatatufuria/terraform-provider-govault/internal/client"
)

func TestWorkloadSessionCoordinatesKnownExpiry(t *testing.T) {
	var logins, sources, secrets atomic.Int32
	started, release := make(chan struct{}), make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/workload/login":
			n := logins.Add(1)
			if n == 2 {
				close(started)
				<-release
			}
			fmt.Fprintf(w, `{"token":"s%d","access_token":"s%d","namespace":"team-a","expires_at":%d}`, n, n, 4102444800+int64(n)*100)
		case "/ns/team-a/secrets/item":
			secrets.Add(1)
			if r.Header.Get("Authorization") != "Bearer s2" {
				t.Errorf("authorization = %q", r.Header.Get("Authorization"))
			}
			_, _ = w.Write([]byte(`{"value":"secret","version":1}`))
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
		}
	}))
	defer server.Close()
	client := testWorkloadClient(t, server)
	session := newWorkloadSession(client, "role", func() (string, error) { sources.Add(1); return "assertion", nil })
	now := time.Unix(0, 0)
	session.now = func() time.Time { return now }
	if err := session.authenticate(context.Background()); err != nil {
		t.Fatal(err)
	}
	now = time.Unix(4102444900, 0)

	const readers = 8
	errs := make(chan error, readers)
	for i := 0; i < readers; i++ {
		go func() { _, err := session.ReadSecret(context.Background(), "app/key", 0); errs <- err }()
	}
	<-started
	close(release)
	for i := 0; i < readers; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if logins.Load() != 2 || sources.Load() != 2 || secrets.Load() != readers || session.generation != 2 {
		t.Fatalf("logins=%d sources=%d secrets=%d generation=%d", logins.Load(), sources.Load(), secrets.Load(), session.generation)
	}
}

func TestWorkloadSessionWaitersCancelIndependentlyAndFlightCleansUp(t *testing.T) {
	var logins atomic.Int32
	started, serverCanceled := make(chan struct{}), make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := logins.Add(1)
		if n == 2 {
			close(started)
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			close(serverCanceled)
			return
		}
		fmt.Fprintf(w, `{"token":"s%d","access_token":"s%d","namespace":"team-a","expires_at":4102445%d00}`, n, n, n)
	}))
	defer server.Close()
	client := testWorkloadClient(t, server)
	session := newWorkloadSession(client, "role", func() (string, error) { return "assertion", nil })
	session.now = func() time.Time { return time.Unix(0, 0) }
	if err := session.authenticate(context.Background()); err != nil {
		t.Fatal(err)
	}
	session.now = func() time.Time { return time.Unix(4102445100, 0) }
	ctx1, cancel1 := context.WithCancel(context.Background())
	ctx2, cancel2 := context.WithCancel(context.Background())
	errs := make(chan error, 2)
	go func() { errs <- session.authenticate(ctx1) }()
	go func() { errs <- session.authenticate(ctx2) }()
	<-started
	waitForWaiters(t, session, 2)
	cancel1()
	if err := <-errs; !errors.Is(err, context.Canceled) {
		t.Fatalf("first waiter error = %v", err)
	}
	select {
	case <-serverCanceled:
		t.Fatal("flight canceled while one waiter remained")
	case <-time.After(30 * time.Millisecond):
	}
	cancel2()
	if err := <-errs; !errors.Is(err, context.Canceled) {
		t.Fatalf("second waiter error = %v", err)
	}
	<-serverCanceled
	if err := session.authenticate(context.Background()); err != nil || logins.Load() != 3 {
		t.Fatalf("later retry error=%v logins=%d", err, logins.Load())
	}
}

func TestWorkloadSessionPreCanceledWorkDoesNoCredentialIO(t *testing.T) {
	var sources, logins atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { logins.Add(1) }))
	defer server.Close()
	session := newWorkloadSession(testWorkloadClient(t, server), "role", func() (string, error) { sources.Add(1); return "assertion", nil })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := session.authenticate(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled error = %v", err)
	}
	flightCtx, cancelFlight := context.WithCancel(context.Background())
	flight := &sessionFlight{ctx: flightCtx, cancel: cancelFlight, done: make(chan struct{}), generation: 1}
	session.flight = flight
	cancelFlight()
	session.runFlight(flight)
	if sources.Load() != 0 || logins.Load() != 0 || session.flight != nil {
		t.Fatalf("sources=%d logins=%d flight=%v", sources.Load(), logins.Load(), session.flight)
	}
}

func TestWorkloadSessionRejectsStaleCommitAndDoesNotReplayUnauthorized(t *testing.T) {
	var logins, secrets atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/workload/login" {
			n := logins.Add(1)
			fmt.Fprintf(w, `{"token":"s%d","access_token":"s%d","namespace":"team-%d","expires_at":4102444800}`, n, n, n)
			return
		}
		if secrets.Add(1) == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/ns/team-2/secrets/item" || r.Header.Get("Authorization") != "Bearer s2" {
			t.Errorf("stale credentials used: path=%q authorization=%q", r.URL.Path, r.Header.Get("Authorization"))
		}
		_, _ = w.Write([]byte(`{"value":"secret","version":1}`))
	}))
	defer server.Close()
	client := testWorkloadClient(t, server)
	session := newWorkloadSession(client, "role", func() (string, error) { return "assertion", nil })
	session.now = func() time.Time { return time.Unix(0, 0) }
	if err := session.authenticate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := session.ReadSecret(context.Background(), "app/key", 0); !errors.Is(err, govaultclient.ErrUnauthorized) {
		t.Fatalf("secret error = %v", err)
	}
	flightCtx, cancel := context.WithCancel(context.Background())
	session.mu.Lock()
	session.next++
	stale := &sessionFlight{ctx: flightCtx, cancel: cancel, done: make(chan struct{}), generation: session.next, waiters: 1}
	session.flight, session.expiresAt = stale, time.Time{}
	session.mu.Unlock()
	session.leaveFlight(stale)
	if err := session.authenticate(context.Background()); err != nil {
		t.Fatalf("new generation: %v", err)
	}
	if err := session.commitFlight(stale, govaultclient.WorkloadSession{Token: "stale", Namespace: "other", ExpiresAt: time.Unix(4102444900, 0)}); !errors.Is(err, context.Canceled) {
		t.Fatalf("stale commit error = %v", err)
	}
	if _, err := session.ReadSecret(context.Background(), "app/key", 0); err != nil {
		t.Fatalf("new generation secret read: %v", err)
	}
	if logins.Load() != 2 || secrets.Load() != 2 || client.Namespace() != "team-2" || session.generation != 3 {
		t.Fatalf("logins=%d secrets=%d namespace=%q generation=%d", logins.Load(), secrets.Load(), client.Namespace(), session.generation)
	}
}

func TestWorkloadSessionFailedFlightAllowsRetry(t *testing.T) {
	var logins atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if logins.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"code":"service_unavailable"}`))
			return
		}
		_, _ = w.Write([]byte(`{"token":"session","access_token":"session","namespace":"team-a","expires_at":4102444800}`))
	}))
	defer server.Close()
	session := newWorkloadSession(testWorkloadClient(t, server), "role", func() (string, error) { return "assertion", nil })
	if err := session.authenticate(context.Background()); !errors.Is(err, govaultclient.ErrServiceUnavailable) {
		t.Fatalf("first error = %v", err)
	}
	if err := session.authenticate(context.Background()); err != nil || logins.Load() != 2 {
		t.Fatalf("retry error=%v logins=%d", err, logins.Load())
	}
}

func testWorkloadClient(t *testing.T, server *httptest.Server) *govaultclient.Client {
	t.Helper()
	client, err := govaultclient.NewProtocolClient(govaultclient.Config{Address: server.URL, CACertFile: writeServerCA(t, server)})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func waitForWaiters(t *testing.T, session *workloadSession, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		session.mu.Lock()
		got := 0
		if session.flight != nil {
			got = session.flight.waiters
		}
		session.mu.Unlock()
		if got == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("flight did not reach %d waiters", want)
}
