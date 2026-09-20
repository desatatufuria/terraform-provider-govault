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
	"strconv"
	"strings"
	"testing"
	"time"
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
	const token, secret = "gv-acceptance-token-canary", "gv-acceptance-secret-canary"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/whoami" {
			_, _ = w.Write([]byte(`{"namespace":"team-a"}`))
			return
		}
		if r.URL.Path != "/ns/team-a/secrets/item" || r.URL.Query().Get("name") != "app/key" {
			t.Errorf("unexpected request %s", r.URL.String())
		}
		_, _ = w.Write([]byte(`{"value":"` + secret + `","version":1}`))
	}))
	defer server.Close()
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	_ = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600)
	config := `terraform { required_version = "~> ` + version + `.0"; required_providers { govault = { source = "desatatufuria/govault" } } }
provider "govault" { address = "` + server.URL + `"; auth_method = "token"; ca_cert_file = "` + ca + `" }
ephemeral "govault_secret" "canary" { path = "app/key" }
output "canary" { value = ephemeral.govault_secret.canary.value; ephemeral = true; sensitive = true }
`
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	cli := filepath.Join(dir, "terraform.rc")
	_ = os.WriteFile(cli, []byte(`provider_installation { dev_overrides { "registry.terraform.io/desatatufuria/govault" = "`+providerDir+`" } direct {} }`), 0o600)
	logPath := filepath.Join(dir, "terraform.log")
	env := append(os.Environ(), "GOVAULT_TOKEN="+token, "TF_CLI_CONFIG_FILE="+cli, "TF_DATA_DIR="+filepath.Join(dir, ".terraform"), "TF_LOG=TRACE", "TF_LOG_PATH="+logPath)
	versionOutput := runAcceptanceCommand(t, dir, env, binary, "version", "-json")
	if !strings.Contains(versionOutput.stdout, `"terraform_version":"`+version+`.`) && !strings.Contains(versionOutput.stdout, `"terraform_version": "`+version+`.`) {
		t.Fatalf("binary is not pinned to Terraform %s", version)
	}
	planOutput := runAcceptanceCommand(t, dir, env, binary, "plan", "-out=tfplan", "-input=false")
	showOutput := runAcceptanceCommand(t, dir, env, binary, "show", "-json", "tfplan")
	applyOutput := runAcceptanceCommand(t, dir, env, binary, "apply", "-input=false", "-auto-approve", "tfplan")
	stateOutput := runAcceptanceCommand(t, dir, env, binary, "state", "pull")
	surfaces := []string{planOutput.stdout, planOutput.stderr, showOutput.stdout, showOutput.stderr, applyOutput.stdout, applyOutput.stderr, stateOutput.stdout, stateOutput.stderr}
	for _, root := range []string{dir, "README.md", "docs", "examples"} {
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err == nil && info.Mode().IsRegular() {
				surfaces = append(surfaces, string(readFile(t, path)))
			}
			return nil
		})
	}
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
	command := exec.CommandContext(ctx, name, args...)
	command.Dir, command.Env = dir, env
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	if err != nil {
		class := "execution failure"
		if ctx.Err() != nil {
			class = "timeout"
		} else if exit, ok := err.(*exec.ExitError); ok {
			class = "exit status " + strconv.Itoa(exit.ExitCode())
		}
		t.Fatalf("%s command failed (%s)", filepath.Base(name), class)
	}
	return acceptanceOutput{stdout: stdout.String(), stderr: stderr.String()}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
