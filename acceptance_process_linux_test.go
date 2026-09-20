//go:build linux

package main

import (
	"os"
	"strconv"
	"strings"
)

func acceptanceDescendantRunning(pid int) bool {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if os.IsNotExist(err) {
		return false
	}
	fields := strings.Fields(string(data))
	return err == nil && len(fields) > 2 && fields[2] != "Z"
}
