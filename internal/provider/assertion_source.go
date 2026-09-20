package provider

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

const maxAssertionBytes = 262144

func readWorkloadAssertion(config providerModel, lookupEnv func(string) (string, bool)) (string, error) {
	hasEnv, hasFile := !config.WorkloadAssertionEnv.IsNull(), !config.WorkloadAssertionFile.IsNull()
	if hasEnv == hasFile {
		return "", fmt.Errorf("configure exactly one workload assertion source")
	}
	var assertion string
	if hasEnv {
		name := config.WorkloadAssertionEnv.ValueString()
		if strings.TrimSpace(name) == "" {
			return "", fmt.Errorf("workload assertion environment selector is empty")
		}
		value, ok := lookupEnv(name)
		if !ok {
			return "", fmt.Errorf("selected workload assertion environment variable is not set")
		}
		assertion = value
	} else {
		path := config.WorkloadAssertionFile.ValueString()
		if strings.TrimSpace(path) == "" {
			return "", fmt.Errorf("workload assertion file selector is empty")
		}
		value, err := readProtectedAssertionFile(path)
		if err != nil {
			return "", err
		}
		assertion = value
	}
	if len(assertion) > maxAssertionBytes || strings.Trim(assertion, " \t\n\r\v\f") == "" || !utf8.ValidString(assertion) {
		return "", fmt.Errorf("workload assertion is empty, invalid UTF-8, or exceeds the size limit")
	}
	return assertion, nil
}
