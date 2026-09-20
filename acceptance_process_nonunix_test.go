//go:build !unix

package main

import (
	"os/exec"
	"time"
)

func configureAcceptanceCommand(command *exec.Cmd) {
	// CommandContext terminates the direct provider process. WaitDelay bounds
	// cleanup when descendants retain inherited pipes on non-Unix platforms.
	command.WaitDelay = 2 * time.Second
}

func acceptanceDescendantRunning(int) bool { return false }
