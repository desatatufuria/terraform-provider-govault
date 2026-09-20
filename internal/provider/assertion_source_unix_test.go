//go:build !windows

package provider

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"golang.org/x/sys/unix"
)

func TestProtectedAssertionFilePolicy(t *testing.T) {
	dir := t.TempDir()
	secure := filepath.Join(dir, "assertion")
	if err := os.WriteFile(secure, []byte("assertion-a"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := readProtectedAssertionFile(secure); err != nil || got != "assertion-a" {
		t.Fatalf("secure file = %q, %v", got, err)
	}
	symlink := filepath.Join(dir, "link")
	if err := os.Symlink(secure, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := readProtectedAssertionFile(symlink); err == nil {
		t.Fatal("symlink must fail closed")
	}
	if err := os.Chmod(secure, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := readProtectedAssertionFile(secure); err == nil {
		t.Fatal("group-readable file must fail closed")
	}
}

func TestProtectedAssertionFIFOIsRejectedWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "assertion.fifo")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { _, err := readProtectedAssertionFile(path); result <- err }()
	select {
	case err := <-result:
		const want = "workload assertion file must be regular, private, and within the size limit"
		if err == nil || err.Error() != want {
			t.Fatalf("FIFO error = %v, want %q", err, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("FIFO read blocked")
	}
}

func TestProtectedAssertionReadsOpenedDescriptorAfterPathReplacement(t *testing.T) {
	dir, path := t.TempDir(), ""
	path = filepath.Join(dir, "assertion")
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := readProtectedAssertionDescriptor(file); err != nil || got != "original" {
		t.Fatalf("descriptor read = %q, %v", got, err)
	}
}

func TestAssertionEnvironmentValidation(t *testing.T) {
	base := providerModel{WorkloadAssertionEnv: types.StringValue("ASSERTION"), WorkloadAssertionFile: types.StringNull()}
	for name, value := range map[string]string{"empty": "", "invalid UTF-8": string([]byte{0xff}), "oversized": string(make([]byte, maxAssertionBytes+1))} {
		t.Run(name, func(t *testing.T) {
			if _, err := readWorkloadAssertion(base, func(string) (string, bool) { return value, true }); err == nil {
				t.Fatal("invalid assertion accepted")
			}
		})
	}
}
