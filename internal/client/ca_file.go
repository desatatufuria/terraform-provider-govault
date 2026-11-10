package client

import (
	"fmt"
	"io"
	"os"
	"syscall"
)

// maxCAFileBytes bounds the CA certificate file. A bundle of every public CA is
// about 200 KiB, so 1 MiB leaves room for a private chain and nothing else.
const maxCAFileBytes = 1 << 20

// readCAFile reads the PEM file named by ca_cert_file. The path comes from the
// provider configuration, so the read must not block or grow without bound
// whatever it points to: it is opened without waiting for a writer (a FIFO would
// otherwise hang Configure), checked on the open descriptor to be a regular file
// within the size limit, and read through a limit. A symbolic link to a regular
// file is accepted, because system CA bundles are commonly linked.
func readCAFile(path string) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: unable to read CA certificate file", ErrInvalidConfiguration)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: CA certificate file must be a regular file", ErrInvalidConfiguration)
	}
	if info.Size() > maxCAFileBytes {
		return nil, fmt.Errorf("%w: CA certificate file exceeds the size limit", ErrInvalidConfiguration)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxCAFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: unable to read CA certificate file", ErrInvalidConfiguration)
	}
	if len(data) > maxCAFileBytes {
		return nil, fmt.Errorf("%w: CA certificate file exceeds the size limit", ErrInvalidConfiguration)
	}
	return data, nil
}
