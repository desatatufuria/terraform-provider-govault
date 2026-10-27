package provider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	govaultclient "github.com/desatatufuria/terraform-provider-govault/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

const parameterTokenCanary = "gv.parameter-token-canary"

// parameterTestServer serves two parameters and a failure per name prefix.
func parameterTestServer(t *testing.T) *govaultclient.Client {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/auth/whoami":
			_, _ = w.Write([]byte(`{"namespace":"team-a"}`))
		case r.URL.Path == "/ns/team-a/parameters/item":
			switch r.URL.Query().Get("name") {
			case "app/log-level":
				_, _ = w.Write([]byte(`{"name":"app/log-level","value":"debug","description":"log verbosity","version":3,"revision":"gv.prev.abc","created":1700000000,"updated":1700003600,"created_by":"alice"}`))
			case "denied":
				w.WriteHeader(http.StatusForbidden)
			case "sealed":
				w.WriteHeader(http.StatusServiceUnavailable)
			case "limited":
				w.WriteHeader(http.StatusTooManyRequests)
			default:
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(parameterTokenCanary))
			}
		case r.URL.Path == "/ns/team-a/parameters/item/versions/2":
			_, _ = w.Write([]byte(`{"name":"app/log-level","value":"info","version":2,"revision":"gv.prev.def","created":1700000000,"updated":1700000100}`))
		case r.URL.Path == "/ns/team-a/parameters/summaries":
			if r.URL.Query().Get("prefix") == "denied/" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			_, _ = w.Write([]byte(`{"parameters":[{"name":"app/log-level","value":"debug","version":3,"revision":"r1","created":1700000000,"updated":1700003600},{"name":"app/region","value":"eu","description":"d","version":1,"revision":"r2","created":1700000000,"updated":1700000000}],"total":2}`))
		default:
			t.Errorf("unexpected request %s", r.URL.String())
		}
	}))
	t.Cleanup(server.Close)
	client, err := govaultclient.New(govaultclient.Config{Address: server.URL, Token: parameterTokenCanary, CACertFile: writeServerCA(t, server)})
	if err != nil || client.Authenticate(context.Background()) != nil {
		t.Fatalf("configure client: %v", err)
	}
	return client
}

func TestParameterDataSourceSchemaAndConfigure(t *testing.T) {
	source := &parameterDataSource{}
	var schemaResponse datasource.SchemaResponse
	source.Schema(context.Background(), datasource.SchemaRequest{}, &schemaResponse)
	if schemaResponse.Diagnostics.HasError() {
		t.Fatalf("schema diagnostics: %v", schemaResponse.Diagnostics)
	}
	attributes := schemaResponse.Schema.Attributes
	if !attributes["name"].IsRequired() || !attributes["version"].IsOptional() || !attributes["version"].IsComputed() {
		t.Error("name must be required and version optional and computed")
	}
	for _, name := range []string{"value", "description", "revision", "created_at", "updated_at", "created_by"} {
		if !attributes[name].IsComputed() {
			t.Errorf("%s must be computed", name)
		}
	}
	if attributes["value"].IsSensitive() {
		t.Error("a parameter value is non-secret by design and must not be sensitive")
	}
	if !strings.Contains(schemaResponse.Schema.MarkdownDescription, "non-secret") || !strings.Contains(schemaResponse.Schema.MarkdownDescription, "ephemeral") {
		t.Error("the description must warn that parameters are for non-secret configuration")
	}
	var configureResponse datasource.ConfigureResponse
	source.Configure(context.Background(), datasource.ConfigureRequest{}, &configureResponse)
	if configureResponse.Diagnostics.HasError() {
		t.Fatalf("nil provider data diagnostics: %v", configureResponse.Diagnostics)
	}
	source.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: "wrong"}, &configureResponse)
	if !configureResponse.Diagnostics.HasError() {
		t.Fatal("wrong provider data must fail")
	}
}

func parameterConfig(t *testing.T, s schema.Schema, name string, version any) tfsdk.Config {
	t.Helper()
	objectType := tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"name": tftypes.String, "version": tftypes.Number, "value": tftypes.String, "description": tftypes.String,
		"revision": tftypes.String, "created_at": tftypes.String, "updated_at": tftypes.String, "created_by": tftypes.String,
	}}
	null := func(typ tftypes.Type) tftypes.Value { return tftypes.NewValue(typ, nil) }
	return tfsdk.Config{Schema: s, Raw: tftypes.NewValue(objectType, map[string]tftypes.Value{
		"name": tftypes.NewValue(tftypes.String, name), "version": tftypes.NewValue(tftypes.Number, version),
		"value": null(tftypes.String), "description": null(tftypes.String), "revision": null(tftypes.String),
		"created_at": null(tftypes.String), "updated_at": null(tftypes.String), "created_by": null(tftypes.String),
	})}
}

func readParameter(t *testing.T, source *parameterDataSource, name string, version any) (parameterModel, datasource.ReadResponse) {
	t.Helper()
	var schemaResponse datasource.SchemaResponse
	source.Schema(context.Background(), datasource.SchemaRequest{}, &schemaResponse)
	config := parameterConfig(t, schemaResponse.Schema, name, version)
	response := datasource.ReadResponse{State: tfsdk.State{Schema: schemaResponse.Schema, Raw: config.Raw}}
	source.Read(context.Background(), datasource.ReadRequest{Config: config}, &response)
	var model parameterModel
	if !response.Diagnostics.HasError() {
		if d := response.State.Get(context.Background(), &model); d.HasError() {
			t.Fatalf("state: %v", d)
		}
	}
	return model, response
}

func TestParameterDataSourceReadsCurrentAndSpecificVersion(t *testing.T) {
	source := &parameterDataSource{client: parameterTestServer(t)}

	model, response := readParameter(t, source, "app/log-level", nil)
	if response.Diagnostics.HasError() {
		t.Fatalf("diagnostics: %v", response.Diagnostics)
	}
	if model.Value != types.StringValue("debug") || model.Version != types.Int64Value(3) || model.Description != types.StringValue("log verbosity") ||
		model.Revision != types.StringValue("gv.prev.abc") || model.UpdatedAt != types.StringValue("2023-11-14T23:13:20Z") ||
		model.CreatedAt != types.StringValue("2023-11-14T22:13:20Z") || model.CreatedBy != types.StringValue("alice") {
		t.Fatalf("model = %#v", model)
	}

	model, response = readParameter(t, source, "app/log-level", 2)
	if response.Diagnostics.HasError() || model.Value != types.StringValue("info") || model.Version != types.Int64Value(2) {
		t.Fatalf("version 2 = %#v, diagnostics = %v", model, response.Diagnostics)
	}
	if model.CreatedBy != types.StringValue("") || model.Description != types.StringValue("") {
		t.Fatalf("absent optional fields must be empty strings: %#v", model)
	}
}

func TestParameterDataSourceFailureDiagnostics(t *testing.T) {
	source := &parameterDataSource{client: parameterTestServer(t)}
	tests := map[string]string{
		"missing": "does not exist", "denied": "not allowed", "sealed": "sealed", "limited": "rate limit",
	}
	for name, want := range tests {
		_, response := readParameter(t, source, name, nil)
		if !response.Diagnostics.HasError() {
			t.Fatalf("%s: expected an error", name)
		}
		text := fmt.Sprint(response.Diagnostics)
		if !strings.Contains(text, want) {
			t.Errorf("%s: diagnostics %q do not mention %q", name, text, want)
		}
		if strings.Contains(text, parameterTokenCanary) {
			t.Errorf("%s: diagnostics leaked the token or response body: %s", name, text)
		}
	}
	_, response := readParameter(t, source, "app/log-level", tftypes.UnknownValue)
	if !response.Diagnostics.HasError() {
		t.Fatal("unknown version must fail")
	}
	var unconfigured datasource.ReadResponse
	(&parameterDataSource{}).Read(context.Background(), datasource.ReadRequest{}, &unconfigured)
	if !unconfigured.Diagnostics.HasError() {
		t.Fatal("read without client must fail")
	}
}

func TestParameterDiagnosticClasses(t *testing.T) {
	for _, err := range []error{govaultclient.ErrUnauthorized, errors.New("other")} {
		if detail := parameterFailureDetail(err); detail == "" {
			t.Errorf("empty detail for %v", err)
		}
	}
}
