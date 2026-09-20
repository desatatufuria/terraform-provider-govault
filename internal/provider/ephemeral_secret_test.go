package provider

import (
	"context"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	govaultclient "github.com/desatatufuria/terraform-provider-govault/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func TestSecretEphemeralSchemaAndConfigure(t *testing.T) {
	resource := &secretEphemeralResource{}
	var schemaResponse ephemeral.SchemaResponse
	resource.Schema(context.Background(), ephemeral.SchemaRequest{}, &schemaResponse)
	if schemaResponse.Diagnostics.HasError() || len(schemaResponse.Schema.Attributes) != 4 {
		t.Fatalf("schema = %#v, diagnostics = %v", schemaResponse.Schema, schemaResponse.Diagnostics)
	}
	for _, name := range []string{"value", "resolved_version"} {
		attribute := schemaResponse.Schema.Attributes[name]
		if !attribute.IsComputed() || !attribute.IsSensitive() {
			t.Errorf("%s must be computed and sensitive", name)
		}
	}
	var configureResponse ephemeral.ConfigureResponse
	resource.Configure(context.Background(), ephemeral.ConfigureRequest{}, &configureResponse)
	if configureResponse.Diagnostics.HasError() {
		t.Fatalf("nil provider data diagnostics: %v", configureResponse.Diagnostics)
	}
	resource.Configure(context.Background(), ephemeral.ConfigureRequest{ProviderData: "wrong"}, &configureResponse)
	if !configureResponse.Diagnostics.HasError() {
		t.Fatal("wrong provider data must fail")
	}
}

func TestSecretEphemeralOpenAndClose(t *testing.T) {
	secretRequests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/whoami" {
			_, _ = w.Write([]byte(`{"namespace":"team-a"}`))
			return
		}
		if r.URL.Path != "/ns/team-a/secrets/item" || r.URL.Query().Get("name") != "app/key" {
			t.Errorf("request URL = %s", r.URL.String())
		}
		secretRequests++
		_, _ = w.Write([]byte(`{"value":"secret-canary","version":3}`))
	}))
	defer server.Close()
	client, err := govaultclient.New(govaultclient.Config{Address: server.URL, Token: "gv.token", CACertFile: writeServerCA(t, server)})
	if err != nil || client.Authenticate(context.Background()) != nil {
		t.Fatalf("configure client: %v", err)
	}
	resource := &secretEphemeralResource{client: client}
	var schemaResponse ephemeral.SchemaResponse
	resource.Schema(context.Background(), ephemeral.SchemaRequest{}, &schemaResponse)
	request, response := secretOpenData(schemaResponse.Schema, nil)
	resource.Open(context.Background(), request, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("open diagnostics: %v", response.Diagnostics)
	}
	var result secretEphemeralModel
	if diagnostics := response.Result.Get(context.Background(), &result); diagnostics.HasError() || result.Value != types.StringValue("secret-canary") || result.ResolvedVersion != types.Int64Value(3) {
		t.Fatalf("result = %#v, diagnostics = %v", result, diagnostics)
	}

	request, response = secretOpenData(schemaResponse.Schema, tftypes.UnknownValue)
	resource.Open(context.Background(), request, &response)
	if !response.Diagnostics.HasError() || secretRequests != 1 {
		t.Fatalf("unknown version diagnostics = %v, secret requests = %d", response.Diagnostics, secretRequests)
	}

	request, response = secretOpenData(schemaResponse.Schema, big.NewFloat(2))
	resource.Open(context.Background(), request, &response)
	if !response.Diagnostics.HasError() || secretRequests != 2 {
		t.Fatalf("mismatched version diagnostics = %v, secret requests = %d", response.Diagnostics, secretRequests)
	}

	resource.Close(context.Background(), ephemeral.CloseRequest{}, &ephemeral.CloseResponse{})
	if resource.client != client {
		t.Fatal("close cleared the shared configured client")
	}
}

func secretOpenData(resourceSchema schema.Schema, version any) (ephemeral.OpenRequest, ephemeral.OpenResponse) {
	objectType := tftypes.Object{AttributeTypes: map[string]tftypes.Type{"path": tftypes.String, "version": tftypes.Number, "value": tftypes.String, "resolved_version": tftypes.Number}}
	raw := tftypes.NewValue(objectType, map[string]tftypes.Value{
		"path": tftypes.NewValue(tftypes.String, "app/key"), "version": tftypes.NewValue(tftypes.Number, version),
		"value": tftypes.NewValue(tftypes.String, nil), "resolved_version": tftypes.NewValue(tftypes.Number, nil),
	})
	return ephemeral.OpenRequest{Config: tfsdk.Config{Raw: raw, Schema: resourceSchema}}, ephemeral.OpenResponse{Result: tfsdk.EphemeralResultData{Raw: raw, Schema: resourceSchema}}
}

func TestSecretEphemeralOpenWithoutClientFails(t *testing.T) {
	var response ephemeral.OpenResponse
	(&secretEphemeralResource{}).Open(context.Background(), ephemeral.OpenRequest{}, &response)
	if !response.Diagnostics.HasError() {
		t.Fatal("open without configured client must fail")
	}
}
