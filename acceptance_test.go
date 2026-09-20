package main

import (
	"bytes"
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	acceptanceTokenCanary       = "gv-acceptance-token-canary"
	acceptanceSecretCanary      = "gv-acceptance-secret-canary"
	acceptanceDiagnosticLimit   = 8 * 1024
	acceptanceDiagnosticOmitted = "\n...[diagnostic truncated]...\n"
)

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
		})
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
	config := `terraform { required_version = "~> ` + version + `.0"; required_providers { govault = { source = "desatatufuria/govault" } } }
provider "govault" { address = "` + server.URL + `"; auth_method = "token"; ca_cert_file = "` + ca + `" }
ephemeral "govault_secret" "canary" { path = "app/key" }
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
	for _, surface := range surfaces {
		for _, canary := range []string{token, secret} {
			if strings.Contains(surface, canary) {
				t.Fatalf("Terraform %s artifact leaked canary", version)
			}
		}
	}
}

type acceptanceOutput struct{ stdout, stderr string }

func runAcceptanceCommand(t *testing.T, dir string, env []string, name string, args ...string) acceptanceOutput {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	output, err, class := executeAcceptanceCommand(ctx, dir, env, name, args...)
	if err != nil {
		t.Fatal(formatAcceptanceFailure(name, args, class, output))
	}
	return output
}

func formatAcceptanceFailure(name string, args []string, class string, output acceptanceOutput) string {
	command := filepath.Base(name)
	if len(args) > 0 {
		command += " " + args[0]
	}
	diagnostic := strings.TrimSpace(output.stderr + "\n" + output.stdout)
	diagnostic = strings.NewReplacer(
		acceptanceTokenCanary, "[REDACTED TOKEN CANARY]",
		acceptanceSecretCanary, "[REDACTED SECRET CANARY]",
	).Replace(diagnostic)
	if len(diagnostic) > acceptanceDiagnosticLimit {
		half := (acceptanceDiagnosticLimit - len(acceptanceDiagnosticOmitted)) / 2
		diagnostic = diagnostic[:half] + acceptanceDiagnosticOmitted + diagnostic[len(diagnostic)-half:]
	}
	if diagnostic == "" {
		diagnostic = "[no command output]"
	}
	return command + " failed (" + class + "):\n" + diagnostic
}

func executeAcceptanceCommand(ctx context.Context, dir string, env []string, name string, args ...string) (acceptanceOutput, error, string) {
	command := exec.CommandContext(ctx, name, args...)
	command.Dir, command.Env = dir, env
	configureAcceptanceCommand(command)
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	output := acceptanceOutput{stdout: stdout.String(), stderr: stderr.String()}
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

func TestFormatAcceptanceFailureIsUsefulBoundedAndRedacted(t *testing.T) {
	padding := strings.Repeat("x", acceptanceDiagnosticLimit)
	got := formatAcceptanceFailure(
		"/verified/terraform",
		[]string{"plan", "-input=false"},
		"exit status 1",
		acceptanceOutput{
			stderr: "useful failure before " + acceptanceTokenCanary + padding + acceptanceSecretCanary + " useful failure after",
		},
	)
	for _, want := range []string{"terraform plan failed (exit status 1)", "useful failure before", "useful failure after", acceptanceDiagnosticOmitted} {
		if !strings.Contains(got, want) {
			t.Fatalf("diagnostic missing %q", want)
		}
	}
	for _, forbidden := range []string{acceptanceTokenCanary, acceptanceSecretCanary} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("diagnostic leaked a canary")
		}
	}
	if len(got) > acceptanceDiagnosticLimit+128 {
		t.Fatalf("diagnostic length = %d", len(got))
	}
}
