package provider

import (
	"context"
	"strings"
	"testing"

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
		"address":      true,
		"auth_method":  true,
		"token_env":    true,
		"ca_cert_file": true,
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

func TestConfigureIsOfflineAndFailsClosed(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		address    any
		authMethod any
		tokenEnv   any
		caCertFile any
		wantError  string
	}{
		"valid selectors": {
			address:    "https://govault.example.com",
			authMethod: "token",
			tokenEnv:   "GOVAULT_TOKEN",
			caCertFile: nil,
		},
		"null optional selectors": {
			address:    "https://govault.example.com",
			authMethod: "token",
			tokenEnv:   nil,
			caCertFile: nil,
		},
		"unsupported authentication": {
			address:    "https://govault.example.com",
			authMethod: "workload",
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
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			p := New("test")()
			s := providerSchema(t)
			request := provider.ConfigureRequest{Config: configFor(s, test.address, test.authMethod, test.tokenEnv, test.caCertFile)}
			var response provider.ConfigureResponse

			p.Configure(context.Background(), request, &response)

			if response.DataSourceData != nil || response.ResourceData != nil || response.EphemeralResourceData != nil {
				t.Fatal("scaffold must leave all provider data unset")
			}
			if test.wantError == "" {
				if response.Diagnostics.HasError() {
					t.Fatalf("unexpected diagnostics: %v", response.Diagnostics)
				}
				return
			}
			if !hasDiagnosticSummary(response.Diagnostics.Errors(), test.wantError) {
				t.Fatalf("missing diagnostic %q in %v", test.wantError, response.Diagnostics)
			}
		})
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

func configFor(s providerschema.Schema, address, authMethod, tokenEnv, caCertFile any) tfsdk.Config {
	objectType := tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"address":      tftypes.String,
		"auth_method":  tftypes.String,
		"token_env":    tftypes.String,
		"ca_cert_file": tftypes.String,
	}}
	return tfsdk.Config{
		Raw: tftypes.NewValue(objectType, map[string]tftypes.Value{
			"address":      tftypes.NewValue(tftypes.String, address),
			"auth_method":  tftypes.NewValue(tftypes.String, authMethod),
			"token_env":    tftypes.NewValue(tftypes.String, tokenEnv),
			"ca_cert_file": tftypes.NewValue(tftypes.String, caCertFile),
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
