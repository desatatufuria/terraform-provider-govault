package provider

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	govaultclient "github.com/desatatufuria/terraform-provider-govault/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

var bundleObjectType = tftypes.Object{AttributeTypes: map[string]tftypes.Type{
	"namespace": tftypes.String, "issuer": tftypes.String, "id": tftypes.String, "pem": tftypes.String,
}}

func bundleSchema() schema.Schema {
	var response datasource.SchemaResponse
	(&pkiBundleDataSource{}).Schema(context.Background(), datasource.SchemaRequest{}, &response)
	return response.Schema
}

func readBundle(t *testing.T, reader bundleReader, namespace, issuer any) (datasource.ReadResponse, pkiBundleModel) {
	t.Helper()
	raw := tftypes.NewValue(bundleObjectType, map[string]tftypes.Value{
		"namespace": tftypes.NewValue(tftypes.String, namespace), "issuer": tftypes.NewValue(tftypes.String, issuer),
		"id": tftypes.NewValue(tftypes.String, nil), "pem": tftypes.NewValue(tftypes.String, nil),
	})
	s := bundleSchema()
	request := datasource.ReadRequest{Config: tfsdk.Config{Raw: raw, Schema: s}}
	response := datasource.ReadResponse{State: tfsdk.State{Raw: raw, Schema: s}}
	(&pkiBundleDataSource{client: reader}).Read(context.Background(), request, &response)
	var model pkiBundleModel
	if !response.Diagnostics.HasError() {
		if diagnostics := response.State.Get(context.Background(), &model); diagnostics.HasError() {
			t.Fatalf("state: %v", diagnostics)
		}
	}
	return response, model
}

func TestPKIBundleSchemaIsPublicAndRegistered(t *testing.T) {
	t.Parallel()

	s := bundleSchema()
	if !s.Attributes["namespace"].IsOptional() || !s.Attributes["issuer"].IsOptional() {
		t.Error("namespace and issuer must be optional")
	}
	for _, name := range []string{"id", "pem"} {
		if !s.Attributes[name].IsComputed() || s.Attributes[name].IsSensitive() {
			t.Errorf("%s must be computed and not sensitive: the bundle is public", name)
		}
	}
	var metadata datasource.MetadataResponse
	(&pkiBundleDataSource{}).Metadata(context.Background(), datasource.MetadataRequest{ProviderTypeName: "govault"}, &metadata)
	if metadata.TypeName != "govault_pki_bundle" {
		t.Fatalf("type name = %q", metadata.TypeName)
	}
	sources := (&goVaultProvider{}).DataSources(context.Background())
	if len(sources) != 1 {
		t.Fatalf("data sources = %d", len(sources))
	}
	var configure datasource.ConfigureResponse
	(&pkiBundleDataSource{}).Configure(context.Background(), datasource.ConfigureRequest{ProviderData: "wrong"}, &configure)
	if !configure.Diagnostics.HasError() {
		t.Fatal("wrong provider data must fail")
	}
}

func TestPKIBundleReadsPublicBundleAndIssuer(t *testing.T) {
	t.Parallel()

	certPEM := "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
	block, _ := pem.Decode([]byte(certPEM))
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "" {
			t.Error("the public routes must not receive credentials")
		}
		switch r.URL.Path {
		case "/pki/public/team-a/ca-bundle.pem":
			_, _ = w.Write([]byte(certPEM + certPEM))
		case "/pki/public/team-a/gv.pki.ca.1/ca.der":
			_, _ = w.Write(block.Bytes)
		default:
			t.Errorf("path = %s", r.URL.Path)
		}
	}))
	defer server.Close()
	client, err := govaultclient.New(govaultclient.Config{Address: server.URL, Token: pkiTokenCanary, CACertFile: writeServerCA(t, server)})
	if err != nil {
		t.Fatal(err)
	}

	response, model := readBundle(t, client, "team-a", nil)
	if response.Diagnostics.HasError() || model.PEM.ValueString() != certPEM+certPEM || model.ID.ValueString() != "team-a" {
		t.Fatalf("bundle = %#v, %v", model, response.Diagnostics)
	}
	response, model = readBundle(t, client, "team-a", "gv.pki.ca.1")
	if response.Diagnostics.HasError() || model.PEM.ValueString() != certPEM || model.ID.ValueString() != "team-a/gv.pki.ca.1" {
		t.Fatalf("issuer = %#v, %v", model, response.Diagnostics)
	}
	if calls.Load() != 2 {
		t.Fatalf("calls = %d", calls.Load())
	}
}

func TestPKIBundleFailuresAreRedacted(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"` + pkiTokenCanary + ` -----BEGIN PRIVATE KEY-----"}`))
	}))
	defer server.Close()
	client, _ := govaultclient.New(govaultclient.Config{Address: server.URL, Token: pkiTokenCanary, CACertFile: writeServerCA(t, server)})
	response, _ := readBundle(t, client, "team-a", nil)
	if !response.Diagnostics.HasError() {
		t.Fatal("404 must fail")
	}
	for _, d := range response.Diagnostics {
		text := d.Summary() + d.Detail()
		if strings.Contains(text, pkiTokenCanary) || strings.Contains(text, "PRIVATE KEY") {
			t.Fatalf("diagnostic leaks: %s", text)
		}
	}
	if response, _ := readBundle(t, client, "Bad Name", nil); !response.Diagnostics.HasError() {
		t.Fatal("invalid namespace must fail")
	}
	if response, _ := readBundle(t, nil, "team-a", nil); !response.Diagnostics.HasError() {
		t.Fatal("missing client must fail")
	}
}

func TestProviderConfigureSharesTheClientWithDataSources(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"namespace":"team-a"}`))
	}))
	defer server.Close()
	p := &goVaultProvider{version: "test", lookupEnv: mapLookup(map[string]string{defaultTokenEnv: pkiTokenCanary})}
	request := provider.ConfigureRequest{Config: configFor(providerSchema(t), server.URL, "token", nil, writeServerCA(t, server))}
	var response provider.ConfigureResponse
	p.Configure(context.Background(), request, &response)
	if response.Diagnostics.HasError() {
		t.Fatalf("configure: %v", response.Diagnostics)
	}
	if !onlyPublicDataSourceData(response.DataSourceData) {
		t.Fatalf("data source data = %T must be the public reader only", response.DataSourceData)
	}
	if _, ok := response.EphemeralResourceData.(certificateSigner); !ok {
		t.Fatalf("ephemeral data = %T", response.EphemeralResourceData)
	}
}

func TestWorkloadSessionSignsAfterAuthenticating(t *testing.T) {
	t.Parallel()

	fake := newFakeGoVaultPKI(t)
	var logins atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/workload/login" {
			logins.Add(1)
			_, _ = w.Write([]byte(`{"token":"session","access_token":"session","namespace":"team-a","expires_at":4102444800}`))
			return
		}
		if r.Header.Get("Authorization") != "Bearer session" {
			t.Errorf("authorization = %q", r.Header.Get("Authorization"))
		}
		fake.handler(w, r)
	}))
	defer server.Close()
	session := newWorkloadSession(testWorkloadClient(t, server), "role", func() (string, error) { return "assertion", nil })
	response, _ := openPKI(t, session, nil)
	if response.Diagnostics.HasError() || logins.Load() != 1 || fake.calls() != 1 {
		t.Fatalf("diagnostics=%v logins=%d signs=%d", response.Diagnostics, logins.Load(), fake.calls())
	}
}
