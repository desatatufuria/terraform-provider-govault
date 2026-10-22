package provider

import (
	"context"
	"sync"
	"time"

	govaultclient "github.com/desatatufuria/terraform-provider-govault/internal/client"
)

type secretReader interface {
	ReadSecret(context.Context, string, int64) (govaultclient.Secret, error)
}

type certificateSigner interface {
	SignCSR(context.Context, string, string, govaultclient.SignRequest) (govaultclient.SignedCertificate, error)
}

type bundleReader interface {
	PublicCABundle(context.Context, string) (string, error)
	PublicIssuerCertificate(context.Context, string, string) (string, error)
}

var (
	_ certificateSigner = (*govaultclient.Client)(nil)
	_ certificateSigner = (*workloadSession)(nil)
	_ bundleReader      = (*govaultclient.Client)(nil)
	_ bundleReader      = (*workloadSession)(nil)
)

type assertionSourceError struct{ error }

type sessionFlight struct {
	ctx        context.Context
	cancel     context.CancelFunc
	done       chan struct{}
	generation uint64
	waiters    int
	err        error
}

type workloadSession struct {
	client    *govaultclient.Client
	roleRef   string
	assertion func() (string, error)
	now       func() time.Time

	mu         sync.Mutex
	generation uint64
	next       uint64
	expiresAt  time.Time
	flight     *sessionFlight
}

func newWorkloadSession(client *govaultclient.Client, roleRef string, assertion func() (string, error)) *workloadSession {
	return &workloadSession{client: client, roleRef: roleRef, assertion: assertion, now: time.Now}
}

func (s *workloadSession) ReadSecret(ctx context.Context, path string, version int64) (govaultclient.Secret, error) {
	if err := s.authenticate(ctx); err != nil {
		return govaultclient.Secret{}, err
	}
	return s.client.ReadSecret(ctx, path, version)
}

func (s *workloadSession) SignCSR(ctx context.Context, namespace, role string, request govaultclient.SignRequest) (govaultclient.SignedCertificate, error) {
	if err := s.authenticate(ctx); err != nil {
		return govaultclient.SignedCertificate{}, err
	}
	return s.client.SignCSR(ctx, namespace, role, request)
}

// The public PKI routes need no credential, so no session is established.
func (s *workloadSession) PublicCABundle(ctx context.Context, namespace string) (string, error) {
	return s.client.PublicCABundle(ctx, namespace)
}

func (s *workloadSession) PublicIssuerCertificate(ctx context.Context, namespace, issuer string) (string, error) {
	return s.client.PublicIssuerCertificate(ctx, namespace, issuer)
}

func (s *workloadSession) authenticate(ctx context.Context) error {
	s.mu.Lock()
	if err := ctx.Err(); err != nil {
		s.mu.Unlock()
		return err
	}
	if s.generation != 0 && s.expiresAt.After(s.now()) {
		s.mu.Unlock()
		return nil
	}
	flight := s.flight
	if flight == nil {
		// The flight owns its context so one departing waiter cannot cancel peers.
		flightCtx, cancel := context.WithCancel(context.Background())
		s.next++
		flight = &sessionFlight{ctx: flightCtx, cancel: cancel, done: make(chan struct{}), generation: s.next}
		s.flight = flight
		go s.runFlight(flight)
	}
	flight.waiters++
	s.mu.Unlock()

	select {
	case <-flight.done:
		return flight.err
	case <-ctx.Done():
		s.leaveFlight(flight)
		return ctx.Err()
	}
}

func (s *workloadSession) leaveFlight(flight *sessionFlight) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.flight != flight {
		return
	}
	flight.waiters--
	if flight.waiters == 0 {
		s.flight = nil
		flight.cancel()
	}
}

func (s *workloadSession) runFlight(flight *sessionFlight) {
	select {
	case <-flight.ctx.Done():
		s.finishFlight(flight, flight.ctx.Err())
		return
	default:
	}
	assertion, err := s.assertion()
	if err != nil {
		err = assertionSourceError{err}
	}
	if err == nil {
		select {
		case <-flight.ctx.Done():
			err = flight.ctx.Err()
		default:
			var session govaultclient.WorkloadSession
			session, err = s.client.LoginWorkload(flight.ctx, s.roleRef, assertion)
			if err == nil {
				err = s.commitFlight(flight, session)
			}
		}
	}

	s.finishFlight(flight, err)
}

func (s *workloadSession) finishFlight(flight *sessionFlight, err error) {
	s.mu.Lock()
	if s.flight == flight {
		s.flight = nil
		flight.err = err
	}
	s.mu.Unlock()
	flight.cancel()
	close(flight.done)
}

func (s *workloadSession) commitFlight(flight *sessionFlight, session govaultclient.WorkloadSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.flight != flight || flight.generation <= s.generation {
		return context.Canceled
	}
	if err := s.client.InstallWorkloadSession(session); err != nil {
		return err
	}
	s.generation, s.expiresAt = flight.generation, session.ExpiresAt
	return nil
}
