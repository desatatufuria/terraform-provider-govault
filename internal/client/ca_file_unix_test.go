//go:build unix

package client

import (
	"errors"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A FIFO with no writer would block an ordinary read for ever and hang Configure.
func TestReadCAFileDoesNotBlockOnAFIFO(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "fifo.pem")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("fifo not available: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := readCAFile(path)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("err = %v, want ErrInvalidConfiguration", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reading a FIFO as the CA file blocked")
	}
}
