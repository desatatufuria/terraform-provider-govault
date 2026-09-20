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
	"unicode/utf8"
)

const (
	acceptanceTokenCanary     = "gv-acceptance-token-canary"
	acceptanceSecretCanary    = "gv-acceptance-secret-canary"
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
	for _, surface := range surfaces {
		for _, canary := range []string{token, secret} {
			if strings.Contains(surface, canary) {
				t.Fatalf("Terraform %s artifact leaked canary", version)
			}
		}
	}
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
	canaries := [][]byte{[]byte(acceptanceTokenCanary), []byte(acceptanceSecretCanary)}
	for _, canary := range canaries {
		boundarySize := min(len(p), len(canary)-1)
		boundary := append(append([]byte(nil), c.scanTail...), p[:boundarySize]...)
		if bytes.Contains(p, canary) || bytes.Contains(boundary, canary) {
			c.protectedCanary = true
		}
	}
	keep := max(len(acceptanceTokenCanary), len(acceptanceSecretCanary)) - 1
	if len(p) >= keep {
		c.scanTail = append(c.scanTail[:0], p[len(p)-keep:]...)
	} else {
		c.scanTail = append(c.scanTail, p...)
		if len(c.scanTail) > keep {
			c.scanTail = append(c.scanTail[:0], c.scanTail[len(c.scanTail)-keep:]...)
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
	for _, canary := range []string{acceptanceTokenCanary, acceptanceSecretCanary} {
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
