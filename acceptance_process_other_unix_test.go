//go:build unix && !linux

package main

import "syscall"

func acceptanceDescendantRunning(pid int) bool {
	return syscall.Kill(pid, 0) == nil
}
