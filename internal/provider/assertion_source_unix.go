//go:build !windows

package provider

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

func readProtectedAssertionFile(path string) (string, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return "", fmt.Errorf("unable to open protected workload assertion file")
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	return readProtectedAssertionDescriptor(file)
}

func readProtectedAssertionDescriptor(file *os.File) (string, error) {
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > maxAssertionBytes {
		return "", fmt.Errorf("workload assertion file must be regular, private, and within the size limit")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxAssertionBytes+1))
	if err != nil || len(data) > maxAssertionBytes {
		return "", fmt.Errorf("unable to read bounded workload assertion file")
	}
	return string(data), nil
}
