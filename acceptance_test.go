package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

const (
	acceptanceTokenCanary     = "gv-acceptance-token-canary"
	acceptanceSecretCanary    = "gv-acceptance-secret-canary"
	acceptanceAssertionCanary = "gv-acceptance-workload-assertion-canary"
	acceptanceForbiddenToken  = "gv-acceptance-forbidden-static-token-canary"
	acceptanceSessionOne      = "gv-acceptance-workload-session-one-canary"
	acceptanceSessionTwo      = "gv-acceptance-workload-session-two-canary"
	acceptanceIntermediate    = "gv-acceptance-workload-intermediate-canary"
	acceptanceTerminalSession = "gv-acceptance-workload-terminal-session-canary"
	acceptanceRawBodyCanary   = "gv-acceptance-raw-http-body-canary"
	acceptanceRoleIDCanary    = "gv-acceptance-approle-role-id-canary"
	acceptanceSecretIDCanary  = "gv-acceptance-approle-secret-id-canary"
	acceptanceAppRoleSession  = "gv-acceptance-approle-session-canary"
	acceptanceCaptureLimit    = 64 * 1024
	acceptanceCaptureOmitted  = "\n...[output omitted]...\n"
	acceptanceUnknownCommand  = "external command"
	acceptanceUnknownFailure  = "execution failure"
	acceptanceNoSafeDiagnosis = "no allowlisted diagnostic"
)

var acceptanceDiagnosticSignals = []string{
	"Invalid character",
	"Invalid single-argument block definition",
	"Unable to read GoVault secret",
	"HTTP 500",
}

func TestTerraformEphemeralAcceptance(t *testing.T) {
	binaries := map[string]string{"1.10": os.Getenv("TF_ACC_TERRAFORM_1_10"), "1.11": os.Getenv("TF_ACC_TERRAFORM_1_11")}
	if binaries["1.10"] == "" && binaries["1.11"] == "" {
		t.Skip("pinned Terraform binaries unavailable; set TF_ACC_TERRAFORM_1_10 and TF_ACC_TERRAFORM_1_11")
	}
	providerDir := t.TempDir()
	providerBinary := filepath.Join(providerDir, "terraform-provider-govault_v0.0.0")
	runAcceptanceCommand(t, ".", nil, "go", "build", "-o", providerBinary, ".")
	for version, binary := range binaries {
		t.Run(version, func(t *testing.T) {
			if binary == "" {
				t.Skip("pinned Terraform " + version + " binary unavailable")
			}
			runTerraformCanary(t, binary, version, providerDir)
			runTerraformWorkloadCanaries(t, binary, version, providerDir)
			runTerraformAppRoleCanaries(t, binary, version, providerDir)
		})
	}
}

func runTerraformAppRoleCanaries(t *testing.T, binary, version, providerDir string) {
	t.Helper()
	for _, scenario := range []struct {
		name, namespace, sessionNamespace, loginPath, secretPath string
	}{
		{name: "root", sessionNamespace: "root", loginPath: "/auth/login", secretPath: "/ns/root/secrets/item"},
		{name: "namespaced", namespace: "team-a", sessionNamespace: "team-a", loginPath: "/ns/team-a/auth/login", secretPath: "/ns/team-a/secrets/item"},
	} {
		t.Run("approle-"+scenario.name, func(t *testing.T) {
			var mu sync.Mutex
			logins, reads := 0, 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				switch r.URL.Path {
				case scenario.loginPath:
					body, err := io.ReadAll(r.Body)
					var request struct {
						Method      string `json:"method"`
						Credentials struct {
							RoleID   string `json:"role_id"`
							SecretID string `json:"secret_id"`
						} `json:"credentials"`
					}
					if err != nil || r.Method != http.MethodPost || r.URL.RawQuery != "" ||
						r.Header.Get("Content-Type") != "application/json" ||
						json.Unmarshal(body, &request) != nil || request.Method != "approle" ||
						request.Credentials.RoleID != acceptanceRoleIDCanary ||
						request.Credentials.SecretID != acceptanceSecretIDCanary {
						t.Error("AppRole login did not contain the expected environment credentials")
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					logins++
					now := time.Now()
					fmt.Fprintf(w, `{"token":%q,"access_token":%q,"namespace":%q,"created_at":%d,"expires_at":%d,"detail":%q}`,
						acceptanceAppRoleSession, acceptanceAppRoleSession, scenario.sessionNamespace,
						now.Unix(), now.Add(10*time.Minute).Unix(), acceptanceRawBodyCanary)
				case scenario.secretPath:
					if r.Header.Get("Authorization") != "Bearer "+acceptanceAppRoleSession {
						t.Error("AppRole secret read did not use the issued session")
						w.WriteHeader(http.StatusUnauthorized)
						return
					}
					reads++
					if r.URL.Query().Get("name") == "server-failure" {
						w.WriteHeader(http.StatusInternalServerError)
						fmt.Fprintf(w, `{"detail":%q}`, acceptanceRawBodyCanary+" "+acceptanceRoleIDCanary+" "+acceptanceSecretIDCanary+" "+acceptanceAppRoleSession)
						return
					}
					if r.URL.Query().Get("name") != "app/key" {
						t.Error("unexpected AppRole secret query")
						w.WriteHeader(http.StatusNotFound)
						return
					}
					fmt.Fprintf(w, `{"value":%q,"version":1}`, acceptanceSecretCanary)
				default:
					t.Error("unexpected AppRole acceptance request")
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()

			dir := t.TempDir()
			ca := filepath.Join(dir, "ca.pem")
			if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600); err != nil {
				t.Fatal("write AppRole acceptance CA")
			}
			config := `terraform {
  required_version = "~> ` + version + `.0"
  required_providers { govault = { source = "desatatufuria/govault" } }
}
provider "govault" {
  address           = "` + server.URL + `"
  auth_method       = "approle"
  ca_cert_file      = "` + ca + `"` + appRoleNamespaceConfig(scenario.namespace) + `
}
ephemeral "govault_secret" "canary" { path = "app/key" }
`
			if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(config), 0o600); err != nil {
				t.Fatal(err)
			}
			cli := filepath.Join(dir, "terraform.rc")
			if err := os.WriteFile(cli, []byte(`provider_installation { dev_overrides { "registry.terraform.io/desatatufuria/govault" = "`+providerDir+`" } }`), 0o600); err != nil {
				t.Fatal(err)
			}
			env := replaceEnv(os.Environ(), "GOVAULT_ROLE_ID="+acceptanceRoleIDCanary, "GOVAULT_SECRET_ID="+acceptanceSecretIDCanary,
				"TF_CLI_CONFIG_FILE="+cli, "TF_DATA_DIR="+filepath.Join(dir, ".terraform"), "TF_LOG=TRACE", "TF_LOG_PATH="+filepath.Join(dir, "terraform.log"))
			planOutput := runAcceptanceCommand(t, dir, env, binary, "plan", "-out=tfplan", "-input=false")
			assertAppRoleCounts(t, &mu, &logins, &reads, 1)
			showOutput := runAcceptanceCommand(t, dir, env, binary, "show", "-json", "tfplan")
			assertAppRoleCounts(t, &mu, &logins, &reads, 1)
			applyOutput := runAcceptanceCommand(t, dir, env, binary, "apply", "-input=false", "-auto-approve", "tfplan")
			assertAppRoleCounts(t, &mu, &logins, &reads, 2)
			stateOutput := runAcceptanceCommand(t, dir, env, binary, "state", "pull")
			assertAppRoleCounts(t, &mu, &logins, &reads, 2)
			surfaces := []string{planOutput.stdout, planOutput.stderr, showOutput.stdout, showOutput.stderr,
				applyOutput.stdout, applyOutput.stderr, stateOutput.stdout, stateOutput.stderr}
			if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(strings.Replace(config, `path = "app/key"`, `path = "server-failure"`, 1)), 0o600); err != nil {
				t.Fatal("write AppRole failure configuration")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			failureOutput, failureErr, _ := executeAcceptanceCommand(ctx, dir, env, binary, "plan", "-input=false")
			cancel()
			if failureOutput.protectedCanary {
				t.Fatal("AppRole failure emitted a protected canary")
			}
			if failureErr == nil || !strings.Contains(failureOutput.stdout+failureOutput.stderr, "Unable to read GoVault secret") {
				t.Fatal("expected sanitized AppRole secret-read failure")
			}
			assertAppRoleCounts(t, &mu, &logins, &reads, 3)
			surfaces = append(surfaces, failureOutput.stdout, failureOutput.stderr)
			artifacts, err := collectAcceptanceSurfaces(dir, "README.md", "docs", "examples")
			if err != nil {
				t.Fatal("collect AppRole acceptance scan surfaces")
			}
			assertNoAcceptanceCanaries(t, version, append(surfaces, artifacts...))
			logAcceptanceHash(t, version+" AppRole "+scenario.name+" TF_LOG", filepath.Join(dir, "terraform.log"))
		})
	}
}

func appRoleNamespaceConfig(namespace string) string {
	if namespace == "" {
		return ""
	}
	return "\n  approle_namespace = \"" + namespace + "\""
}

func assertAppRoleCounts(t *testing.T, mu *sync.Mutex, logins, reads *int, want int) {
	t.Helper()
	mu.Lock()
	defer mu.Unlock()
	if *logins != want || *reads != want {
		t.Fatalf("AppRole requests = logins %d, reads %d; want %d each", *logins, *reads, want)
	}
}

type workloadAcceptanceState struct {
	mu                              sync.Mutex
	successLogins, successSecrets   int
	terminalLogins, terminalSecrets int
	deniedLogins, deniedSecrets     int
	firstExpiry                     time.Time
}

func runTerraformWorkloadCanaries(t *testing.T, binary, version, providerDir string) {
	t.Helper()
	state := &workloadAcceptanceState{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state.handle(t, w, r)
	}))
	defer server.Close()

	root := t.TempDir()
	ca := filepath.Join(root, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal("write workload acceptance CA")
	}
	successDir, successEnv := writeWorkloadAcceptanceFixture(t, root, "success", binary, version, providerDir, server.URL, ca, "success", `
ephemeral "govault_secret" "first" {
  path = "first"
}
ephemeral "govault_secret" "second" {
  path = ephemeral.govault_secret.first.value
}`)
	planOutput := runAcceptanceCommand(t, successDir, successEnv, binary, "plan", "-out=tfplan", "-input=false")
	showOutput := runAcceptanceCommand(t, successDir, successEnv, binary, "show", "-json", "tfplan")
	applyOutput := runAcceptanceCommand(t, successDir, successEnv, binary, "apply", "-input=false", "-auto-approve", "tfplan")
	stateOutput := runAcceptanceCommand(t, successDir, successEnv, binary, "state", "pull")
	surfaces := []string{
		planOutput.stdout, planOutput.stderr, showOutput.stdout, showOutput.stderr,
		applyOutput.stdout, applyOutput.stderr, stateOutput.stdout, stateOutput.stderr,
	}

	terminalDir, terminalEnv := writeWorkloadAcceptanceFixture(t, root, "terminal", binary, version, providerDir, server.URL, ca, "terminal", `
ephemeral "govault_secret" "terminal" {
  path = "terminal-401"
}`)
	runExpectedWorkloadFailure(t, terminalDir, terminalEnv, binary, "Unable to read GoVault secret")

	deniedDir, deniedEnv := writeWorkloadAcceptanceFixture(t, root, "denied", binary, version, providerDir, server.URL, ca, "denied", `
ephemeral "govault_secret" "denied" {
  path = "must-not-run"
}`)
	runExpectedWorkloadFailure(t, deniedDir, deniedEnv, binary, "GoVault workload authentication failed")

	state.mu.Lock()
	counts := []int{state.successLogins, state.successSecrets, state.terminalLogins, state.terminalSecrets, state.deniedLogins, state.deniedSecrets}
	state.mu.Unlock()
	if fmt.Sprint(counts) != "[3 4 1 1 1 0]" {
		t.Fatalf("workload request counts = %v, want [3 4 1 1 1 0]", counts)
	}
	artifactSurfaces, err := collectAcceptanceSurfaces(root, "README.md", "docs", "examples")
	if err != nil {
		t.Fatal("collect workload acceptance scan surfaces")
	}
	surfaces = append(surfaces, artifactSurfaces...)
	assertNoAcceptanceCanaries(t, version, surfaces)
	for _, name := range []string{"success", "terminal", "denied"} {
		logAcceptanceHash(t, version+" workload "+name+" TF_LOG", filepath.Join(root, name, "terraform.log"))
	}
}

func (s *workloadAcceptanceState) handle(t *testing.T, w http.ResponseWriter, r *http.Request) {
	t.Helper()
	if r.URL.Path == "/auth/workload/login" {
		body, err := io.ReadAll(r.Body)
		var request struct {
			RoleRef   string `json:"role_ref"`
			Assertion string `json:"assertion"`
		}
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		if err != nil || r.Method != http.MethodPost || r.URL.RawQuery != "" || r.Header.Get("Content-Type") != "application/json" ||
			requestContainsForbiddenToken(r, body) || decoder.Decode(&request) != nil || decoder.Decode(&struct{}{}) != io.EOF ||
			request.Assertion != acceptanceAssertionCanary {
			t.Error("workload login did not contain only the expected public credentials")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		switch request.RoleRef {
		case "success":
			s.successLogins++
			token, expires := acceptanceSessionTwo, time.Now().Add(10*time.Minute)
			if s.successLogins == 1 {
				token, s.firstExpiry = acceptanceSessionOne, time.Now().Add(4*time.Second)
				expires = s.firstExpiry
			}
			fmt.Fprintf(w, `{"token":%q,"access_token":%q,"namespace":"team-a","expires_at":%d}`, token, token, expires.Unix())
		case "terminal":
			s.terminalLogins++
			fmt.Fprintf(w, `{"token":%q,"access_token":%q,"namespace":"team-a","expires_at":%d}`, acceptanceTerminalSession, acceptanceTerminalSession, time.Now().Add(10*time.Minute).Unix())
		case "denied":
			s.deniedLogins++
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintf(w, `{"code":"unauthenticated","detail":%q}`, acceptanceRawBodyCanary)
		default:
			t.Error("unexpected workload role reference")
			w.WriteHeader(http.StatusBadRequest)
		}
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if r.URL.Path != "/ns/team-a/secrets/item" {
		t.Error("unexpected workload secret path")
		w.WriteHeader(http.StatusNotFound)
		return
	}
	switch r.URL.Query().Get("name") {
	case "first":
		s.successSecrets++
		expected := acceptanceSessionTwo
		if s.successSecrets == 1 {
			expected = acceptanceSessionOne
		}
		if r.Header.Get("Authorization") != "Bearer "+expected {
			t.Error("first secret request used the wrong session generation")
		}
		if s.successSecrets == 1 {
			wait := time.Until(s.firstExpiry.Add(250 * time.Millisecond))
			s.mu.Unlock()
			if wait > 0 {
				time.Sleep(wait)
			}
			s.mu.Lock()
		}
		fmt.Fprintf(w, `{"value":%q,"version":1}`, acceptanceIntermediate)
	case acceptanceIntermediate:
		s.successSecrets++
		if r.Header.Get("Authorization") != "Bearer "+acceptanceSessionTwo {
			t.Error("dependent secret request did not use the renewed session")
		}
		fmt.Fprintf(w, `{"value":%q,"version":1}`, acceptanceSecretCanary)
	case "terminal-401":
		s.terminalSecrets++
		if r.Header.Get("Authorization") != "Bearer "+acceptanceTerminalSession {
			t.Error("terminal secret request used the wrong session")
		}
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, `{"detail":%q}`, acceptanceRawBodyCanary)
	default:
		s.deniedSecrets++
		t.Error("unexpected workload secret request")
		w.WriteHeader(http.StatusNotFound)
	}
}

func writeWorkloadAcceptanceFixture(t *testing.T, root, name, binary, version, providerDir, address, ca, role, resources string) (string, []string) {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	config := `terraform {
  required_version = "~> ` + version + `.0"
  required_providers { govault = { source = "desatatufuria/govault" } }
}
provider "govault" {
  address                = "` + address + `"
  auth_method            = "workload"
  workload_role_ref      = "` + role + `"
  workload_assertion_env = "GOVAULT_ACCEPTANCE_ASSERTION"
  ca_cert_file           = "` + ca + `"
}
` + resources + "\n"
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	cli := filepath.Join(dir, "terraform.rc")
	if err := os.WriteFile(cli, []byte(`provider_installation { dev_overrides { "registry.terraform.io/desatatufuria/govault" = "`+providerDir+`" } }`), 0o600); err != nil {
		t.Fatal(err)
	}
	env := replaceEnv(os.Environ(), "GOVAULT_ACCEPTANCE_ASSERTION="+acceptanceAssertionCanary, "GOVAULT_TOKEN="+acceptanceForbiddenToken, "TF_CLI_CONFIG_FILE="+cli, "TF_DATA_DIR="+filepath.Join(dir, ".terraform"), "TF_LOG=TRACE", "TF_LOG_PATH="+filepath.Join(dir, "terraform.log"))
	versionOutput := runAcceptanceCommand(t, dir, env, binary, "version", "-json")
	if !strings.Contains(versionOutput.stdout, `"terraform_version":"`+version+`.`) && !strings.Contains(versionOutput.stdout, `"terraform_version": "`+version+`.`) {
		t.Fatalf("binary is not pinned to Terraform %s", version)
	}
	return dir, env
}

func requestContainsForbiddenToken(r *http.Request, body []byte) bool {
	if strings.Contains(r.URL.String(), acceptanceForbiddenToken) ||
		strings.Contains(r.RequestURI, acceptanceForbiddenToken) ||
		strings.Contains(r.Host, acceptanceForbiddenToken) ||
		bytes.Contains(body, []byte(acceptanceForbiddenToken)) {
		return true
	}
	for name, values := range r.Header {
		if strings.Contains(name, acceptanceForbiddenToken) {
			return true
		}
		for _, value := range values {
			if strings.Contains(value, acceptanceForbiddenToken) {
				return true
			}
		}
	}
	return false
}

func runExpectedWorkloadFailure(t *testing.T, dir string, env []string, binary, signal string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	output, err, _ := executeAcceptanceCommand(ctx, dir, env, binary, "plan", "-input=false")
	if output.protectedCanary {
		t.Fatal("Terraform failure emitted a protected workload canary")
	}
	if err == nil || !strings.Contains(output.stdout+output.stderr, signal) {
		t.Fatalf("expected sanitized workload failure class %q", signal)
	}
}

func runTerraformCanary(t *testing.T, binary, version, providerDir string) {
	t.Helper()
	const token, secret = acceptanceTokenCanary, acceptanceSecretCanary
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			t.Error("request did not contain the exact acceptance bearer")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/auth/whoami" {
			_, _ = w.Write([]byte(`{"namespace":"team-a"}`))
			return
		}
		if r.URL.Path != "/ns/team-a/secrets/item" {
			t.Errorf("unexpected request path or query")
		}
		if r.URL.Query().Get("name") == "server-failure" {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(token + " " + secret))
			return
		}
		if r.URL.Query().Get("name") != "app/key" {
			t.Error("unexpected secret query")
		}
		_, _ = w.Write([]byte(`{"value":"` + secret + `","version":1}`))
	}))
	defer server.Close()
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal("write acceptance CA")
	}
	config := `terraform {
  required_version = "~> ` + version + `.0"
  required_providers {
    govault = {
      source = "desatatufuria/govault"
    }
  }
}
provider "govault" {
  address      = "` + server.URL + `"
  auth_method  = "token"
  ca_cert_file = "` + ca + `"
}
ephemeral "govault_secret" "canary" {
  path = "app/key"
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	cli := filepath.Join(dir, "terraform.rc")
	if err := os.WriteFile(cli, []byte(`provider_installation { dev_overrides { "registry.terraform.io/desatatufuria/govault" = "`+providerDir+`" } }`), 0o600); err != nil {
		t.Fatal("write Terraform CLI configuration")
	}
	logPath := filepath.Join(dir, "terraform.log")
	env := replaceEnv(os.Environ(), "GOVAULT_TOKEN="+token, "TF_CLI_CONFIG_FILE="+cli, "TF_DATA_DIR="+filepath.Join(dir, ".terraform"), "TF_LOG=TRACE", "TF_LOG_PATH="+logPath)
	versionOutput := runAcceptanceCommand(t, dir, env, binary, "version", "-json")
	if !strings.Contains(versionOutput.stdout, `"terraform_version":"`+version+`.`) && !strings.Contains(versionOutput.stdout, `"terraform_version": "`+version+`.`) {
		t.Fatalf("binary is not pinned to Terraform %s", version)
	}
	planOutput := runAcceptanceCommand(t, dir, env, binary, "plan", "-out=tfplan", "-input=false")
	showOutput := runAcceptanceCommand(t, dir, env, binary, "show", "-json", "tfplan")
	applyOutput := runAcceptanceCommand(t, dir, env, binary, "apply", "-input=false", "-auto-approve", "tfplan")
	stateOutput := runAcceptanceCommand(t, dir, env, binary, "state", "pull")
	surfaces := []string{planOutput.stdout, planOutput.stderr, showOutput.stdout, showOutput.stderr, applyOutput.stdout, applyOutput.stderr, stateOutput.stdout, stateOutput.stderr}
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(strings.Replace(config, `path = "app/key"`, `path = "server-failure"`, 1)), 0o600); err != nil {
		t.Fatal("write expected-failure configuration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	failureOutput, failureErr, _ := executeAcceptanceCommand(ctx, dir, env, binary, "plan", "-input=false")
	cancel()
	if failureOutput.protectedCanary {
		t.Fatal("terraform plan emitted a protected canary")
	}
	if failureErr == nil {
		t.Fatal("secret-bearing server failure unexpectedly passed")
	}
	failureDiagnostics := failureOutput.stdout + failureOutput.stderr
	if !strings.Contains(failureDiagnostics, "Unable to read GoVault secret") || !strings.Contains(failureDiagnostics, "HTTP 500") {
		t.Fatal("expected failure did not expose only the stable sanitized diagnostic class")
	}
	surfaces = append(surfaces, failureOutput.stdout, failureOutput.stderr)
	artifactSurfaces, err := collectAcceptanceSurfaces(dir, "README.md", "docs", "examples")
	if err != nil {
		t.Fatal("collect acceptance scan surfaces")
	}
	surfaces = append(surfaces, artifactSurfaces...)
	assertNoAcceptanceCanaries(t, version, surfaces)
	logAcceptanceHash(t, version+" token TF_LOG", logPath)
}

func logAcceptanceHash(t *testing.T, label, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", label, err)
	}
	t.Logf("%s sha256=%x bytes=%d", label, sha256.Sum256(data), len(data))
}

type acceptanceOutput struct {
	stdout, stderr  string
	protectedCanary bool
}

func runAcceptanceCommand(t *testing.T, dir string, env []string, name string, args ...string) acceptanceOutput {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	output, err, class := executeAcceptanceCommand(ctx, dir, env, name, args...)
	if output.protectedCanary {
		t.Fatalf("%s emitted a protected canary", safeAcceptanceCommand(name, args))
	}
	if err != nil {
		t.Fatal(formatAcceptanceFailure(name, args, class, output))
	}
	return output
}

func formatAcceptanceFailure(name string, args []string, class string, output acceptanceOutput) string {
	signals := make([]string, 0, len(acceptanceDiagnosticSignals))
	combined := output.stderr + "\n" + output.stdout
	for _, signal := range acceptanceDiagnosticSignals {
		if strings.Contains(combined, signal) {
			signals = append(signals, signal)
		}
	}
	if len(signals) == 0 {
		signals = append(signals, acceptanceNoSafeDiagnosis)
	}
	return safeAcceptanceCommand(name, args) + " failed (" + safeAcceptanceClass(class) + "); diagnostics: " + strings.Join(signals, ", ")
}

func safeAcceptanceCommand(name string, args []string) string {
	command := acceptanceUnknownCommand
	switch filepath.Base(name) {
	case "terraform":
		command = "terraform"
	case "go":
		command = "go"
	}
	if len(args) == 0 {
		return command
	}
	allowed := map[string]bool{"apply": true, "build": true, "plan": true, "show": true, "state": true, "version": true}
	if allowed[args[0]] {
		return command + " " + args[0]
	}
	return command
}

func safeAcceptanceClass(class string) string {
	if class == "timeout" || class == acceptanceUnknownFailure {
		return class
	}
	const prefix = "exit status "
	if strings.HasPrefix(class, prefix) {
		status, err := strconv.Atoi(strings.TrimPrefix(class, prefix))
		if err == nil && status >= 0 && status <= 255 {
			return prefix + strconv.Itoa(status)
		}
	}
	return acceptanceUnknownFailure
}

func executeAcceptanceCommand(ctx context.Context, dir string, env []string, name string, args ...string) (acceptanceOutput, error, string) {
	command := exec.CommandContext(ctx, name, args...)
	command.Dir, command.Env = dir, env
	configureAcceptanceCommand(command)
	stdout, stderr := newAcceptanceCapture(), newAcceptanceCapture()
	command.Stdout, command.Stderr = stdout, stderr
	err := command.Run()
	output := acceptanceOutput{
		stdout:          stdout.String(),
		stderr:          stderr.String(),
		protectedCanary: stdout.protectedCanary || stderr.protectedCanary,
	}
	if err != nil {
		class := "execution failure"
		if ctx.Err() != nil {
			class = "timeout"
		} else if exit, ok := err.(*exec.ExitError); ok {
			class = "exit status " + strconv.Itoa(exit.ExitCode())
		}
		return output, err, class
	}
	return output, nil, "success"
}

type acceptanceCapture struct {
	head, tail      []byte
	scanTail        []byte
	total           int64
	protectedCanary bool
}

func newAcceptanceCapture() *acceptanceCapture {
	return &acceptanceCapture{
		head: make([]byte, 0, acceptanceCaptureLimit/2),
		tail: make([]byte, 0, acceptanceCaptureLimit/2),
	}
}

func (c *acceptanceCapture) Write(p []byte) (int, error) {
	written := len(p)
	c.total += int64(written)
	c.scanProtectedCanaries(p)

	headRemaining := cap(c.head) - len(c.head)
	if headRemaining > 0 {
		keep := min(headRemaining, len(p))
		c.head = append(c.head, p[:keep]...)
		p = p[keep:]
	}
	if len(p) > 0 {
		tailLimit := acceptanceCaptureLimit / 2
		if len(p) >= tailLimit {
			c.tail = append(c.tail[:0], p[len(p)-tailLimit:]...)
		} else {
			if overflow := len(c.tail) + len(p) - tailLimit; overflow > 0 {
				copy(c.tail, c.tail[overflow:])
				c.tail = c.tail[:len(c.tail)-overflow]
			}
			c.tail = append(c.tail, p...)
		}
	}
	return written, nil
}

func (c *acceptanceCapture) scanProtectedCanaries(p []byte) {
	keep := 0
	for _, value := range acceptanceProtectedCanaries() {
		canary := []byte(value)
		boundarySize := min(len(p), len(canary)-1)
		boundary := append(append([]byte(nil), c.scanTail...), p[:boundarySize]...)
		if bytes.Contains(p, canary) || bytes.Contains(boundary, canary) {
			c.protectedCanary = true
		}
		keep = max(keep, len(canary)-1)
	}
	if len(p) >= keep {
		c.scanTail = append(c.scanTail[:0], p[len(p)-keep:]...)
	} else {
		c.scanTail = append(c.scanTail, p...)
		if len(c.scanTail) > keep {
			c.scanTail = append(c.scanTail[:0], c.scanTail[len(c.scanTail)-keep:]...)
		}
	}
}

func acceptanceProtectedCanaries() []string {
	return []string{
		acceptanceTokenCanary, acceptanceSecretCanary, acceptanceAssertionCanary,
		acceptanceForbiddenToken, acceptanceSessionOne, acceptanceSessionTwo,
		acceptanceIntermediate, acceptanceTerminalSession, acceptanceRawBodyCanary,
		acceptanceRoleIDCanary, acceptanceSecretIDCanary, acceptanceAppRoleSession,
	}
}

func assertNoAcceptanceCanaries(t *testing.T, version string, surfaces []string) {
	t.Helper()
	for _, surface := range surfaces {
		for _, canary := range acceptanceProtectedCanaries() {
			if strings.Contains(surface, canary) {
				t.Fatalf("Terraform %s artifact leaked a protected canary", version)
			}
		}
	}
}

func (c *acceptanceCapture) String() string {
	data := append(append([]byte(nil), c.head...), c.tail...)
	if c.total > int64(len(data)) {
		data = append(append(append([]byte(nil), c.head...), acceptanceCaptureOmitted...), c.tail...)
	}
	data = bytes.ToValidUTF8(data, []byte("�"))
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || r >= ' ' && r != 0x7f {
			return r
		}
		return -1
	}, string(data))
}

func collectAcceptanceSurfaces(roots ...string) ([]string, error) {
	var surfaces []string
	for _, root := range roots {
		if err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			surfaces = append(surfaces, string(data))
			return nil
		}); err != nil {
			return nil, err
		}
	}
	return surfaces, nil
}

func replaceEnv(base []string, replacements ...string) []string {
	keys := make(map[string]bool, len(replacements))
	for _, value := range replacements {
		keys[strings.SplitN(value, "=", 2)[0]] = true
	}
	result := make([]string, 0, len(base)+len(replacements))
	for _, value := range base {
		if !keys[strings.SplitN(value, "=", 2)[0]] {
			result = append(result, value)
		}
	}
	return append(result, replacements...)
}

func TestAcceptanceTimeoutKillsDescendants(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("process-group regression requires Linux process inspection")
	}
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	_, err, class := executeAcceptanceCommand(ctx, ".", nil, "sh", "-c", `sleep 30 & echo $! > "$1"; wait`, "sh", pidFile)
	if err == nil || class != "timeout" {
		t.Fatalf("command result = %v, class = %s", err, class)
	}
	data, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal("timeout helper did not record its child")
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatal("timeout helper recorded an invalid child")
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !acceptanceDescendantRunning(pid) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("timed-out command left a descendant running")
}

func TestReplaceEnvRemovesInheritedDuplicates(t *testing.T) {
	got := replaceEnv([]string{"KEEP=1", "TOKEN=old", "TOKEN=older"}, "TOKEN=new")
	if strings.Join(got, ",") != "KEEP=1,TOKEN=new" {
		t.Fatalf("environment = %q", got)
	}
}

func TestFormatAcceptanceFailureAllowsOnlyStructuredSignals(t *testing.T) {
	unknownSecret := "unregistered-secret-value"
	got := formatAcceptanceFailure(
		"/hostile/"+unknownSecret,
		[]string{"plan\x1b[31m" + unknownSecret},
		"exit status 1\x00"+unknownSecret,
		acceptanceOutput{
			stderr: "\xff\x1b[31mInvalid character\x00 " + acceptanceTokenCanary + " " + acceptanceSecretCanary + " " + unknownSecret,
		},
	)
	for _, want := range []string{acceptanceUnknownCommand, acceptanceUnknownFailure, "Invalid character"} {
		if !strings.Contains(got, want) {
			t.Fatalf("diagnostic missing %q", want)
		}
	}
	for _, forbidden := range []string{acceptanceTokenCanary, acceptanceSecretCanary, unknownSecret, "\x1b", "\x00"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("diagnostic leaked unsafe output")
		}
	}
	if !utf8.ValidString(got) {
		t.Fatal("diagnostic is not valid UTF-8")
	}
}

func TestAcceptanceCaptureIsBoundedSanitizedAndScansEntireStream(t *testing.T) {
	capture := newAcceptanceCapture()
	large := append([]byte("\xff\x1b[31m"), bytes.Repeat([]byte("x"), acceptanceCaptureLimit*2)...)
	if _, err := capture.Write(large); err != nil {
		t.Fatal(err)
	}
	if _, err := capture.Write([]byte("gv-acceptance-token-")); err != nil {
		t.Fatal(err)
	}
	if _, err := capture.Write([]byte("canary tail Invalid character\x00")); err != nil {
		t.Fatal(err)
	}
	got := capture.String()
	if len(got) > acceptanceCaptureLimit+len(acceptanceCaptureOmitted)+len("�") {
		t.Fatalf("capture length = %d", len(got))
	}
	if !capture.protectedCanary {
		t.Fatal("capture missed a canary split across writes")
	}
	if !utf8.ValidString(got) || strings.ContainsAny(got, "\x00\x1b\x7f") {
		t.Fatal("capture retained invalid UTF-8 or terminal controls")
	}
	if !strings.Contains(got, "Invalid character") || !strings.Contains(got, acceptanceCaptureOmitted) {
		t.Fatal("capture did not preserve bounded tail evidence")
	}
}

func TestAcceptanceCaptureDetectsEveryCanaryAcrossWrites(t *testing.T) {
	for _, canary := range acceptanceProtectedCanaries() {
		t.Run(canary, func(t *testing.T) {
			capture := newAcceptanceCapture()
			middle := len(canary) / 2
			_, _ = capture.Write([]byte(canary[:middle]))
			_, _ = capture.Write([]byte(canary[middle:]))
			if !capture.protectedCanary {
				t.Fatal("capture missed a protected canary split across writes")
			}
		})
	}
}
