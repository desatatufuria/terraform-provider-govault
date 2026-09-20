//go:build windows

package provider

import "fmt"

func readProtectedAssertionFile(string) (string, error) {
	return "", fmt.Errorf("workload assertion files are not supported on Windows; use workload_assertion_env")
}
