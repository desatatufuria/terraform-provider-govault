package main

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/desatatufuria/terraform-provider-govault/internal/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
)

func TestProtocol6ProviderSchema(t *testing.T) {
	t.Parallel()

	server, err := providerserver.NewProtocol6WithError(provider.New("test")())()
	if err != nil {
		t.Fatalf("create protocol 6 server: %v", err)
	}
	response, err := server.GetProviderSchema(context.Background(), &tfprotov6.GetProviderSchemaRequest{})
	if err != nil {
		t.Fatalf("get provider schema: %v", err)
	}
	if len(response.Diagnostics) != 0 {
		t.Fatalf("protocol diagnostics: %v", response.Diagnostics)
	}
	if response.Provider == nil {
		t.Fatal("protocol 6 server returned no provider schema")
	}
	if len(response.ResourceSchemas) != 0 || len(response.DataSourceSchemas) != 0 || len(response.EphemeralResourceSchemas) != 0 {
		t.Fatal("PHE-001 scaffold must not register functional resources")
	}
}

func TestRegistryManifestDeclaresOnlyProtocol6(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("terraform-registry-manifest.json")
	if err != nil {
		t.Fatalf("read registry manifest: %v", err)
	}
	var manifest struct {
		Version  int `json:"version"`
		Metadata struct {
			ProtocolVersions []string `json:"protocol_versions"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("parse registry manifest: %v", err)
	}
	if manifest.Version != 1 || len(manifest.Metadata.ProtocolVersions) != 1 || manifest.Metadata.ProtocolVersions[0] != "6.0" {
		t.Fatalf("unexpected registry manifest: %+v", manifest)
	}
}

func TestRepositoryDocumentsFrozenIdentityAndFloor(t *testing.T) {
	t.Parallel()

	for _, file := range []string{"README.md", "examples/provider/provider.tf"} {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		content := string(data)
		if !strings.Contains(content, ">= 1.10.0") {
			t.Errorf("%s does not document the Terraform 1.10 floor", file)
		}
		if !strings.Contains(content, "desatatufuria/govault") {
			t.Errorf("%s does not contain the Registry namespace and type", file)
		}
		if strings.Contains(content, "token =") {
			t.Errorf("%s must not show an inline token", file)
		}
	}
}
