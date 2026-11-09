package client

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadCAFileAcceptsARegularFileAndASymlinkToOne(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(path, []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.pem")
	if err := os.Symlink(path, link); err != nil {
		t.Skipf("symlinks are not available: %v", err)
	}
	for name, p := range map[string]string{"file": path, "symlink": link} {
		data, err := readCAFile(p)
		if err != nil || !strings.Contains(string(data), "BEGIN CERTIFICATE") {
			t.Fatalf("%s: data = %q, err = %v", name, data, err)
		}
	}
}

func TestReadCAFileRefusesWhatIsNotABoundedRegularFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	big := filepath.Join(dir, "big.pem")
	if err := os.WriteFile(big, make([]byte, maxCAFileBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := map[string]string{
		"larger than the limit": big,
		"a directory":           dir,
		"missing":               filepath.Join(dir, "missing.pem"),
	}
	for name, path := range tests {
		if data, err := readCAFile(path); err == nil || data != nil || !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("%s: data = %v, err = %v, want ErrInvalidConfiguration and no data", name, data, err)
		}
	}
}
