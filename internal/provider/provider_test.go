package provider

import (
	"context"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	govaultclient "github.com/desatatufuria/terraform-provider-govault/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	providerschema "github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func TestMetadata(t *testing.T) {
	t.Parallel()

	p := New("1.2.3")()
	var response provider.MetadataResponse
	p.Metadata(context.Background(), provider.MetadataRequest{}, &response)

	if response.TypeName != "govault" {
		t.Fatalf("unexpected type name %q", response.TypeName)
	}
	if response.Version != "1.2.3" {
		t.Fatalf("unexpected version %q", response.Version)
	}
	if RegistryAddress != "registry.terraform.io/desatatufuria/govault" {
		t.Fatalf("unexpected registry address %q", RegistryAddress)
	}
}

func TestSchemaContainsOnlyNonSecretSelectors(t *testing.T) {
	t.Parallel()

	s := providerSchema(t)
	want := map[string]bool{
		"address": true, "auth_method": true, "token_env": true, "ca_cert_file": true,
		"workload_role_ref": true, "workload_assertion_env": true, "workload_assertion_file": true,
	}
	if len(s.Attributes) != len(want) {
		t.Fatalf("got %d attributes, want %d: %#v", len(s.Attributes), len(want), s.Attributes)
	}
	for name := range s.Attributes {
		if !want[name] {
			t.Errorf("unexpected provider attribute %q", name)
		}
	}
	if _, exists := s.Attributes["token"]; exists {
		t.Fatal("provider schema must not expose an inline token")
	}
}

func TestConfigureRejectsInvalidSelectorsBeforeIO(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		address    any
		authMethod any
		tokenEnv   any
		caCertFile any
		workload   []any
		wantError  string
	}{
		"unsupported authentication": {
			address:    "https://govault.example.com",
			authMethod: "other",
			tokenEnv:   nil,
			caCertFile: nil,
			wantError:  "Unsupported authentication method",
		},
		"missing address": {
			address:    nil,
			authMethod: "token",
			tokenEnv:   nil,
			caCertFile: nil,
			wantError:  "Missing GoVault address",
		},
		"missing authentication": {
			address:    "https://govault.example.com",
			authMethod: nil,
			tokenEnv:   nil,
			caCertFile: nil,
			wantError:  "Missing authentication method",
		},
		"unknown required selector": {
			address:    tftypes.UnknownValue,
			authMethod: "token",
			tokenEnv:   nil,
			caCertFile: nil,
			wantError:  "Unknown provider configuration",
		},
		"unknown optional selector": {
			address:    "https://govault.example.com",
			authMethod: "token",
			tokenEnv:   tftypes.UnknownValue,
			caCertFile: nil,
			wantError:  "Unknown provider configuration",
		},
		"empty token environment selector": {
			address:    "https://govault.example.com",
			authMethod: "token",
			tokenEnv:   "",
			caCertFile: nil,
			wantError:  "Missing token environment selector",
		},
		"token rejects workload selector": {
			address: "https://govault.example.com", authMethod: "token", workload: []any{"role", nil, nil},
			wantError: "Invalid token authentication selectors",
		},
		"workload requires role": {
			address: "https://govault.example.com", authMethod: "workload", workload: []any{nil, "ASSERTION", nil},
			wantError: "Missing workload role reference",
		},
		"workload rejects token selector": {
			address: "https://govault.example.com", authMethod: "workload", tokenEnv: "TOKEN", workload: []any{"role", "ASSERTION", nil},
			wantError: "Invalid workload authentication selectors",
		},
		"workload requires exactly one source": {
			address: "https://govault.example.com", authMethod: "workload", workload: []any{"role", nil, nil},
			wantError: "Invalid workload assertion source",
		},
		"workload rejects dual source": {
			address: "https://govault.example.com", authMethod: "workload", workload: []any{"role", "ASSERTION", "/assertion"},
			wantError: "Invalid workload assertion source",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			p := &goVaultProvider{version: "test", lookupEnv: func(string) (string, bool) {
				t.Fatal("invalid local configuration must not read the environment")
				return "", false
			}}
			s := providerSchema(t)
			request := provider.ConfigureRequest{Config: configFor(s, test.address, test.authMethod, test.tokenEnv, test.caCertFile, test.workload...)}
			var response provider.ConfigureResponse

			p.Configure(context.Background(), request, &response)

			if response.DataSourceData != nil || response.ResourceData != nil || response.EphemeralResourceData != nil {
				t.Fatal("scaffold must leave all provider data unset")
			}
			if !hasDiagnosticSummary(response.Diagnostics.Errors(), test.wantError) {
				t.Fatalf("missing diagnostic %q in %v", test.wantError, response.Diagnostics)
			}
		})
	}
}

func TestConfigureAuthenticatesUsingOnlySelectedEnvironment(t *testing.T) {
	const token = "gv.selected-token"

	tests := map[string]struct {
		tokenEnv     any
		lookup       func(string) (string, bool)
		wantLookup   string
		wantError    string
		wantRequests int
	}{
		"default selector": {
			tokenEnv:     nil,
			lookup:       mapLookup(map[string]string{defaultTokenEnv: token}),
			wantLookup:   defaultTokenEnv,
			wantRequests: 1,
		},
		"explicit selector": {
			tokenEnv:     "CUSTOM_GOVAULT_TOKEN",
			lookup:       mapLookup(map[string]string{"CUSTOM_GOVAULT_TOKEN": token}),
			wantLookup:   "CUSTOM_GOVAULT_TOKEN",
			wantRequests: 1,
		},
		"no fallback": {
			tokenEnv:     "CUSTOM_GOVAULT_TOKEN",
			lookup:       mapLookup(map[string]string{defaultTokenEnv: token}),
			wantLookup:   "CUSTOM_GOVAULT_TOKEN",
			wantError:    "Missing GoVault token",
			wantRequests: 0,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var requestedEnv string
			requests := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				if got := r.Header.Get("Authorization"); got != "Bearer "+token {
					t.Errorf("authorization header = %q", got)
				}
				_, _ = w.Write([]byte(`{"namespace":"team-a"}`))
			}))
			defer server.Close()

			caFile := writeServerCA(t, server)
			p := &goVaultProvider{version: "test", lookupEnv: func(name string) (string, bool) {
				requestedEnv = name
				return test.lookup(name)
			}}
			s := providerSchema(t)
			request := provider.ConfigureRequest{Config: configFor(s, server.URL, "token", test.tokenEnv, caFile)}
			var response provider.ConfigureResponse

			p.Configure(context.Background(), request, &response)

			if requestedEnv != test.wantLookup {
				t.Fatalf("environment lookup = %q, want %q", requestedEnv, test.wantLookup)
			}
			if requests != test.wantRequests {
				t.Fatalf("requests = %d, want %d", requests, test.wantRequests)
			}
			if test.wantError != "" {
				if !hasDiagnosticSummary(response.Diagnostics.Errors(), test.wantError) {
					t.Fatalf("missing diagnostic %q in %v", test.wantError, response.Diagnostics)
				}
				return
			}
			if response.Diagnostics.HasError() {
				t.Fatalf("unexpected diagnostics: %v", response.Diagnostics)
			}
			configuredClient, ok := response.EphemeralResourceData.(*govaultclient.Client)
			if !ok || configuredClient.Namespace() != "team-a" {
				t.Fatalf("unexpected ephemeral provider data: %#v", response.EphemeralResourceData)
			}
			if response.DataSourceData != nil || response.ResourceData != nil {
				t.Fatal("PHE-002 must not configure state-bearing provider data")
			}
		})
	}
}

func TestConfigureWorkloadLoginThenReadsSecret(t *testing.T) {
	const assertion, session = "external-assertion", "gv.workload-session"
	var paths []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		switch r.URL.Path {
		case "/auth/workload/login":
			if r.Header.Get("Authorization") != "" {
				t.Error("workload login sent authorization header")
			}
			_, _ = w.Write([]byte(`{"token":"` + session + `","access_token":"` + session + `","namespace":"team-a","expires_at":4102444800}`))
		case "/ns/team-a/secrets/item":
			if r.Header.Get("Authorization") != "Bearer "+session {
				t.Errorf("authorization = %q", r.Header.Get("Authorization"))
			}
			_, _ = w.Write([]byte(`{"value":"secret","version":1}`))
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
		}
	}))
	defer server.Close()
	p := &goVaultProvider{lookupEnv: mapLookup(map[string]string{"OIDC_ASSERTION": assertion})}
	s := providerSchema(t)
	request := provider.ConfigureRequest{Config: configFor(s, server.URL, workloadAuth, nil, writeServerCA(t, server), "role-a", "OIDC_ASSERTION", nil)}
	var response provider.ConfigureResponse
	p.Configure(context.Background(), request, &response)
	client, ok := response.EphemeralResourceData.(secretReader)
	if response.Diagnostics.HasError() || !ok {
		t.Fatalf("configure diagnostics = %v", response.Diagnostics)
	}
	if _, err := client.ReadSecret(context.Background(), "app/key", 0); err != nil {
		t.Fatalf("read secret: %v", err)
	}
	if strings.Join(paths, ",") != "/auth/workload/login,/ns/team-a/secrets/item" {
		t.Fatalf("paths = %v", paths)
	}
}

func TestConfigureClassifiesLocalAssertionSourceFailure(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("local source failure reached network") }))
	defer server.Close()
	p := &goVaultProvider{lookupEnv: mapLookup(nil)}
	s := providerSchema(t)
	request := provider.ConfigureRequest{Config: configFor(s, server.URL, workloadAuth, nil, writeServerCA(t, server), "role-a", "MISSING_ASSERTION", nil)}
	var response provider.ConfigureResponse
	p.Configure(context.Background(), request, &response)
	if !hasDiagnosticSummary(response.Diagnostics.Errors(), "Invalid workload assertion source") || hasDiagnosticSummary(response.Diagnostics.Errors(), "GoVault workload authentication failed") {
		t.Fatalf("diagnostics = %v", response.Diagnostics)
	}
}

func TestConfigureDiagnosticsRedactTokenAndResponseBody(t *testing.T) {
	const (
		token  = "gv.provider-canary"
		secret = "provider-response-secret"
	)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(token + " " + secret))
	}))
	defer server.Close()

	p := &goVaultProvider{version: "test", lookupEnv: mapLookup(map[string]string{defaultTokenEnv: token})}
	s := providerSchema(t)
	request := provider.ConfigureRequest{Config: configFor(s, server.URL, "token", nil, writeServerCA(t, server))}
	var response provider.ConfigureResponse
	p.Configure(context.Background(), request, &response)

	if !response.Diagnostics.HasError() {
		t.Fatal("expected authentication diagnostic")
	}
	diagnostics := fmt.Sprint(response.Diagnostics)
	for _, value := range []string{token, secret} {
		if strings.Contains(diagnostics, value) {
			t.Fatalf("diagnostics leaked %q: %s", value, diagnostics)
		}
	}
}

func providerSchema(t *testing.T) providerschema.Schema {
	t.Helper()
	p := New("test")()
	var response provider.SchemaResponse
	p.Schema(context.Background(), provider.SchemaRequest{}, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("schema diagnostics: %v", response.Diagnostics)
	}
	return response.Schema
}

func configFor(s providerschema.Schema, address, authMethod, tokenEnv, caCertFile any, workload ...any) tfsdk.Config {
	values := []any{nil, nil, nil}
	copy(values, workload)
	objectType := tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"address":           tftypes.String,
		"auth_method":       tftypes.String,
		"token_env":         tftypes.String,
		"ca_cert_file":      tftypes.String,
		"workload_role_ref": tftypes.String, "workload_assertion_env": tftypes.String, "workload_assertion_file": tftypes.String,
	}}
	return tfsdk.Config{
		Raw: tftypes.NewValue(objectType, map[string]tftypes.Value{
			"address":                 tftypes.NewValue(tftypes.String, address),
			"auth_method":             tftypes.NewValue(tftypes.String, authMethod),
			"token_env":               tftypes.NewValue(tftypes.String, tokenEnv),
			"ca_cert_file":            tftypes.NewValue(tftypes.String, caCertFile),
			"workload_role_ref":       tftypes.NewValue(tftypes.String, values[0]),
			"workload_assertion_env":  tftypes.NewValue(tftypes.String, values[1]),
			"workload_assertion_file": tftypes.NewValue(tftypes.String, values[2]),
		}),
		Schema: s,
	}
}

func hasDiagnosticSummary(diagnostics diag.Diagnostics, want string) bool {
	for _, diagnostic := range diagnostics {
		if strings.Contains(diagnostic.Summary(), want) {
			return true
		}
	}
	return false
}

func mapLookup(values map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	}
}

func writeServerCA(t *testing.T, server *httptest.Server) string {
	t.Helper()
	certificate := server.Certificate()
	if certificate == nil {
		t.Fatal("test server has no certificate")
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write CA: %v", err)
	}
	return path
}
