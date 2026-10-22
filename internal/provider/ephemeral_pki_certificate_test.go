package provider

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	govaultclient "github.com/desatatufuria/terraform-provider-govault/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

const pkiTokenCanary = "gv.pki-token-canary"

// fakeGoVaultPKI is a sign route backed by a throwaway CA.
type fakeGoVaultPKI struct {
	t       *testing.T
	caKey   *ecdsa.PrivateKey
	caCert  *x509.Certificate
	caPEM   string
	mu      sync.Mutex
	bodies  []string
	paths   []string
	status  int                              // 0 means 201
	swapKey crypto.PublicKey                 // sign for this key instead of the CSR key
	body    map[string]json.RawMessage       // parsed last body
	hook    func(map[string]json.RawMessage) // optional
}

func newFakeGoVaultPKI(t *testing.T) *fakeGoVaultPKI {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &fakeGoVaultPKI{t: t, caKey: key, caCert: cert, caPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
}

func (f *fakeGoVaultPKI) handler(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.bodies = append(f.bodies, string(raw))
	f.paths = append(f.paths, r.URL.Path)
	f.mu.Unlock()
	if f.status != 0 && f.status != http.StatusCreated {
		w.WriteHeader(f.status)
		_, _ = w.Write([]byte(`{"error":"refused ` + pkiTokenCanary + ` -----BEGIN PRIVATE KEY-----"}`))
		return
	}
	var body struct {
		CSR string `json:"csr_pem"`
		TTL int64  `json:"ttl_seconds"`
	}
	_ = json.Unmarshal(raw, &body)
	block, _ := pem.Decode([]byte(body.CSR))
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var public crypto.PublicKey = csr.PublicKey
	if f.swapKey != nil {
		public = f.swapKey
	}
	ttl := time.Duration(body.TTL) * time.Second
	if ttl == 0 {
		ttl = 24 * time.Hour
	}
	notBefore := time.Now().Add(-time.Minute).Truncate(time.Second)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(0x1a2b), Subject: csr.Subject, DNSNames: csr.DNSNames, NotBefore: notBefore, NotAfter: notBefore.Add(ttl)}
	der, err := x509.CreateCertificate(rand.Reader, leaf, f.caCert, public, f.caKey)
	if err != nil {
		f.t.Errorf("sign: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	answer, _ := json.Marshal(map[string]any{
		"id": "gv.pki.cert.1", "certificate_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		"issuing_ca_pem": f.caPEM, "ca_chain_pem": f.caPEM + f.caPEM, "serial_number": "1a2b", "not_after": leaf.NotAfter.Unix(),
		"issuer_ca_id": "gv.pki.ca.1", "issuer_serial": "01",
	})
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write(answer)
}

func (f *fakeGoVaultPKI) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.bodies)
}

func (f *fakeGoVaultPKI) client(t *testing.T) (*govaultclient.Client, *httptest.Server) {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(f.handler))
	t.Cleanup(server.Close)
	client, err := govaultclient.New(govaultclient.Config{Address: server.URL, Token: pkiTokenCanary, CACertFile: writeServerCA(t, server)})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.InstallWorkloadSession(govaultclient.WorkloadSession{Token: pkiTokenCanary, Namespace: "team-a", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	return client, server
}

var (
	pkiStringList = tftypes.List{ElementType: tftypes.String}
	pkiObjectType = tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"namespace": tftypes.String, "role": tftypes.String, "common_name": tftypes.String,
		"alt_names": pkiStringList, "ip_sans": pkiStringList, "uri_sans": pkiStringList, "email_sans": pkiStringList,
		"ttl": tftypes.String, "key_type": tftypes.String, "self": tftypes.Bool,
		"id": tftypes.String, "certificate": tftypes.String, "private_key": tftypes.String, "chain": tftypes.String,
		"ca_certificate": tftypes.String, "serial": tftypes.String, "not_before": tftypes.String, "not_after": tftypes.String,
		"expires_in_seconds": tftypes.Number,
	}}
)

func pkiList(values ...string) tftypes.Value {
	elements := make([]tftypes.Value, 0, len(values))
	for _, value := range values {
		elements = append(elements, tftypes.NewValue(tftypes.String, value))
	}
	return tftypes.NewValue(pkiStringList, elements)
}

func pkiConfig(overrides map[string]tftypes.Value) tftypes.Value {
	values := map[string]tftypes.Value{}
	for name, typ := range pkiObjectType.AttributeTypes {
		values[name] = tftypes.NewValue(typ, nil)
	}
	values["role"] = tftypes.NewValue(tftypes.String, "web")
	values["common_name"] = tftypes.NewValue(tftypes.String, "api.example.test")
	for name, value := range overrides {
		values[name] = value
	}
	return tftypes.NewValue(pkiObjectType, values)
}

func pkiSchema() schema.Schema {
	var response ephemeral.SchemaResponse
	(&pkiCertificateEphemeralResource{}).Schema(context.Background(), ephemeral.SchemaRequest{}, &response)
	return response.Schema
}

func openPKI(t *testing.T, signer certificateSigner, overrides map[string]tftypes.Value) (ephemeral.OpenResponse, pkiCertificateModel) {
	t.Helper()
	raw := pkiConfig(overrides)
	resourceSchema := pkiSchema()
	request := ephemeral.OpenRequest{Config: tfsdk.Config{Raw: raw, Schema: resourceSchema}}
	response := ephemeral.OpenResponse{Result: tfsdk.EphemeralResultData{Raw: raw, Schema: resourceSchema}}
	(&pkiCertificateEphemeralResource{client: signer}).Open(context.Background(), request, &response)
	var model pkiCertificateModel
	if !response.Diagnostics.HasError() {
		if diagnostics := response.Result.Get(context.Background(), &model); diagnostics.HasError() {
			t.Fatalf("result: %v", diagnostics)
		}
	}
	return response, model
}

func diagnosticText(response ephemeral.OpenResponse) string {
	var builder strings.Builder
	for _, d := range response.Diagnostics {
		builder.WriteString(d.Summary() + " " + d.Detail() + "\n")
	}
	return builder.String()
}

func str(value string) tftypes.Value { return tftypes.NewValue(tftypes.String, value) }

func TestPKICertificateSchema(t *testing.T) {
	t.Parallel()

	resourceSchema := pkiSchema()
	for _, name := range []string{"role"} {
		if !resourceSchema.Attributes[name].IsRequired() {
			t.Errorf("%s must be required", name)
		}
	}
	for _, name := range []string{"namespace", "common_name", "alt_names", "ip_sans", "uri_sans", "email_sans", "ttl", "key_type", "self"} {
		if !resourceSchema.Attributes[name].IsOptional() {
			t.Errorf("%s must be optional", name)
		}
	}
	for _, name := range []string{"id", "certificate", "private_key", "chain", "ca_certificate", "serial", "not_before", "not_after", "expires_in_seconds"} {
		if !resourceSchema.Attributes[name].IsComputed() {
			t.Errorf("%s must be computed", name)
		}
	}
	if !resourceSchema.Attributes["private_key"].IsSensitive() {
		t.Error("private_key must be sensitive")
	}
	for _, name := range []string{"certificate", "chain", "ca_certificate", "serial"} {
		if resourceSchema.Attributes[name].IsSensitive() {
			t.Errorf("%s is public material and must not be sensitive", name)
		}
	}
}

func TestPKICertificateIsEphemeralOnlyAndRegistered(t *testing.T) {
	t.Parallel()

	var _ ephemeral.EphemeralResourceWithConfigure = (*pkiCertificateEphemeralResource)(nil)
	var _ ephemeral.EphemeralResourceWithValidateConfig = (*pkiCertificateEphemeralResource)(nil)
	var metadata ephemeral.MetadataResponse
	(&pkiCertificateEphemeralResource{}).Metadata(context.Background(), ephemeral.MetadataRequest{ProviderTypeName: "govault"}, &metadata)
	if metadata.TypeName != "govault_pki_certificate" {
		t.Fatalf("type name = %q", metadata.TypeName)
	}
	found := false
	for _, factory := range (&goVaultProvider{}).EphemeralResources(context.Background()) {
		var m ephemeral.MetadataResponse
		factory().Metadata(context.Background(), ephemeral.MetadataRequest{ProviderTypeName: "govault"}, &m)
		found = found || m.TypeName == "govault_pki_certificate"
	}
	if !found {
		t.Fatal("govault_pki_certificate is not registered")
	}
	var configure ephemeral.ConfigureResponse
	(&pkiCertificateEphemeralResource{}).Configure(context.Background(), ephemeral.ConfigureRequest{ProviderData: "wrong"}, &configure)
	if !configure.Diagnostics.HasError() {
		t.Fatal("wrong provider data must fail")
	}
}

func validatePKI(t *testing.T, overrides map[string]tftypes.Value) ephemeral.ValidateConfigResponse {
	t.Helper()
	request := ephemeral.ValidateConfigRequest{Config: tfsdk.Config{Raw: pkiConfig(overrides), Schema: pkiSchema()}}
	var response ephemeral.ValidateConfigResponse
	(&pkiCertificateEphemeralResource{}).ValidateConfig(context.Background(), request, &response)
	return response
}

func TestPKICertificateValidateConfig(t *testing.T) {
	t.Parallel()

	unknown := tftypes.NewValue(tftypes.String, tftypes.UnknownValue)
	for name, test := range map[string]struct {
		overrides map[string]tftypes.Value
		wantError bool
	}{
		"plain":                 {nil, false},
		"self without names":    {map[string]tftypes.Value{"self": tftypes.NewValue(tftypes.Bool, true), "common_name": tftypes.NewValue(tftypes.String, nil)}, false},
		"self with common name": {map[string]tftypes.Value{"self": tftypes.NewValue(tftypes.Bool, true)}, true},
		"self with dns":         {map[string]tftypes.Value{"self": tftypes.NewValue(tftypes.Bool, true), "common_name": tftypes.NewValue(tftypes.String, nil), "alt_names": pkiList("a.example.test")}, true},
		"self with ip":          {map[string]tftypes.Value{"self": tftypes.NewValue(tftypes.Bool, true), "common_name": tftypes.NewValue(tftypes.String, nil), "ip_sans": pkiList("10.0.0.1")}, true},
		"self with uri":         {map[string]tftypes.Value{"self": tftypes.NewValue(tftypes.Bool, true), "common_name": tftypes.NewValue(tftypes.String, nil), "uri_sans": pkiList("spiffe://x/y")}, true},
		"self with email":       {map[string]tftypes.Value{"self": tftypes.NewValue(tftypes.Bool, true), "common_name": tftypes.NewValue(tftypes.String, nil), "email_sans": pkiList("a@b.test")}, true},
		"no names, not self":    {map[string]tftypes.Value{"common_name": tftypes.NewValue(tftypes.String, nil)}, true},
		"bad ttl":               {map[string]tftypes.Value{"ttl": str("soon")}, true},
		"good ttl":              {map[string]tftypes.Value{"ttl": str("24h")}, false},
		"bad key type":          {map[string]tftypes.Value{"key_type": str("dsa")}, true},
		"rsa 4096":              {map[string]tftypes.Value{"key_type": str("rsa-4096")}, false},
		"unknown common name":   {map[string]tftypes.Value{"common_name": unknown}, false},
		"unknown self":          {map[string]tftypes.Value{"self": tftypes.NewValue(tftypes.Bool, tftypes.UnknownValue), "alt_names": pkiList("a.example.test")}, false},
		"bad namespace":         {map[string]tftypes.Value{"namespace": str("Team A")}, true},
	} {
		response := validatePKI(t, test.overrides)
		if response.Diagnostics.HasError() != test.wantError {
			t.Errorf("%s: diagnostics = %v, want error %v", name, response.Diagnostics, test.wantError)
		}
	}
}

func TestPKICertificateOpenIssuesCertificateForALocalKey(t *testing.T) {
	t.Parallel()

	fake := newFakeGoVaultPKI(t)
	client, _ := fake.client(t)
	response, model := openPKI(t, client, map[string]tftypes.Value{
		"namespace": str("team-b"), "alt_names": pkiList("api.example.test", "www.example.test"), "ttl": str("2h"),
	})
	if response.Diagnostics.HasError() {
		t.Fatalf("diagnostics: %v", response.Diagnostics)
	}
	if fake.calls() != 1 || fake.paths[0] != "/ns/team-b/pki/sign/web" {
		t.Fatalf("calls = %d, paths = %v", fake.calls(), fake.paths)
	}
	// Only a CSR (and the permitted fields) left the process.
	var sent map[string]any
	if err := json.Unmarshal([]byte(fake.bodies[0]), &sent); err != nil {
		t.Fatal(err)
	}
	for field := range sent {
		if field != "csr_pem" && field != "common_name" && field != "ttl_seconds" {
			t.Errorf("unexpected request field %q", field)
		}
	}
	if sent["ttl_seconds"] != float64(7200) {
		t.Errorf("ttl_seconds = %v", sent["ttl_seconds"])
	}
	if strings.Contains(fake.bodies[0], "PRIVATE KEY") {
		t.Fatal("request body contains a private key block")
	}
	keyBlock, _ := pem.Decode([]byte(model.PrivateKey.ValueString()))
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" {
		t.Fatal("private_key is not PKCS#8 PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(fake.bodies[0], strings.ReplaceAll(strings.Split(model.PrivateKey.ValueString(), "\n")[1], "\\", "")) {
		t.Fatal("request body contains private key material")
	}
	certBlock, _ := pem.Decode([]byte(model.Certificate.ValueString()))
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil || !parsed.(*ecdsa.PrivateKey).Public().(*ecdsa.PublicKey).Equal(cert.PublicKey) {
		t.Fatalf("certificate does not match private_key: %v", err)
	}
	if model.Serial.ValueString() != "1a2b" || model.ID.ValueString() != "gv.pki.cert.1" || model.Chain.ValueString() != fake.caPEM+fake.caPEM || model.CACertificate.ValueString() != fake.caPEM {
		t.Fatalf("outputs = %#v", model)
	}
	notAfter, err := time.Parse(time.RFC3339, model.NotAfter.ValueString())
	if err != nil || !notAfter.Equal(cert.NotAfter) {
		t.Fatalf("not_after = %q, %v", model.NotAfter.ValueString(), err)
	}
	if _, err := time.Parse(time.RFC3339, model.NotBefore.ValueString()); err != nil {
		t.Fatalf("not_before = %q", model.NotBefore.ValueString())
	}
	if seconds := model.ExpiresInSeconds.ValueInt64(); seconds < 7000 || seconds > 7200 {
		t.Fatalf("expires_in_seconds = %d", seconds)
	}
}

func TestPKICertificateOpenDefaultsToSessionNamespace(t *testing.T) {
	t.Parallel()

	fake := newFakeGoVaultPKI(t)
	client, _ := fake.client(t)
	if response, _ := openPKI(t, client, nil); response.Diagnostics.HasError() {
		t.Fatalf("diagnostics: %v", response.Diagnostics)
	}
	if fake.paths[0] != "/ns/team-a/pki/sign/web" {
		t.Fatalf("path = %s", fake.paths[0])
	}
}

func TestPKICertificateKeyTypes(t *testing.T) {
	t.Parallel()

	for keyType, check := range map[string]func(any) bool{
		"ecdsa-p384": func(k any) bool { key, ok := k.(*ecdsa.PrivateKey); return ok && key.Curve == elliptic.P384() },
		"rsa-2048":   func(k any) bool { key, ok := k.(*rsa.PrivateKey); return ok && key.N.BitLen() == 2048 },
	} {
		fake := newFakeGoVaultPKI(t)
		client, _ := fake.client(t)
		response, model := openPKI(t, client, map[string]tftypes.Value{"key_type": str(keyType)})
		if response.Diagnostics.HasError() {
			t.Fatalf("%s: %v", keyType, response.Diagnostics)
		}
		block, _ := pem.Decode([]byte(model.PrivateKey.ValueString()))
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil || !check(key) {
			t.Errorf("%s: key = %T, %v", keyType, key, err)
		}
	}
}

func TestPKICertificateSelfSendsNoNames(t *testing.T) {
	t.Parallel()

	fake := newFakeGoVaultPKI(t)
	client, _ := fake.client(t)
	response, _ := openPKI(t, client, map[string]tftypes.Value{"self": tftypes.NewValue(tftypes.Bool, true), "common_name": tftypes.NewValue(tftypes.String, nil)})
	if response.Diagnostics.HasError() {
		t.Fatalf("diagnostics: %v", response.Diagnostics)
	}
	var sent map[string]string
	_ = json.Unmarshal([]byte(fake.bodies[0]), &sent)
	if _, ok := sent["common_name"]; ok {
		t.Fatal("self-issue must not send common_name")
	}
	block, _ := pem.Decode([]byte(sent["csr_pem"]))
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.Subject.CommonName != "" || len(csr.DNSNames) != 0 {
		t.Fatalf("self-issue CSR must carry no names: %v", err)
	}
}

func TestPKICertificateOpenRefusesSelfWithNamesBeforeAnyRequest(t *testing.T) {
	t.Parallel()

	fake := newFakeGoVaultPKI(t)
	client, _ := fake.client(t)
	response, _ := openPKI(t, client, map[string]tftypes.Value{"self": tftypes.NewValue(tftypes.Bool, true)})
	if !response.Diagnostics.HasError() || fake.calls() != 0 {
		t.Fatalf("diagnostics = %v, calls = %d", response.Diagnostics, fake.calls())
	}
}

func TestPKICertificateOpenRefusesUnknownInputsAndMissingClient(t *testing.T) {
	t.Parallel()

	fake := newFakeGoVaultPKI(t)
	client, _ := fake.client(t)
	for _, name := range []string{"role", "namespace", "common_name", "ttl", "key_type"} {
		response, _ := openPKI(t, client, map[string]tftypes.Value{name: tftypes.NewValue(tftypes.String, tftypes.UnknownValue)})
		if !response.Diagnostics.HasError() {
			t.Errorf("unknown %s must fail", name)
		}
	}
	if fake.calls() != 0 {
		t.Fatalf("calls = %d", fake.calls())
	}
	if response, _ := openPKI(t, nil, nil); !response.Diagnostics.HasError() {
		t.Fatal("open without a client must fail")
	}
}

func TestPKICertificateOpenRefusesCertificateForAnotherKey(t *testing.T) {
	t.Parallel()

	fake := newFakeGoVaultPKI(t)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	fake.swapKey = other.Public()
	client, _ := fake.client(t)
	response, model := openPKI(t, client, nil)
	if !response.Diagnostics.HasError() {
		t.Fatal("a certificate for another key must be refused")
	}
	text := diagnosticText(response)
	if !strings.Contains(text, "not for the generated key") || strings.Contains(text, "BEGIN") {
		t.Fatalf("diagnostic = %q", text)
	}
	if !model.PrivateKey.IsNull() || fake.calls() != 1 {
		t.Fatalf("outputs must stay unset; calls = %d", fake.calls())
	}
}

func TestPKICertificateOpenSurfacesRefusalsWithoutSecretsOrRetry(t *testing.T) {
	t.Parallel()

	for _, status := range []int{400, 403, 409, 429, 500, 503} {
		fake := newFakeGoVaultPKI(t)
		fake.status = status
		client, _ := fake.client(t)
		response, _ := openPKI(t, client, nil)
		if !response.Diagnostics.HasError() {
			t.Fatalf("status %d: expected error", status)
		}
		text := diagnosticText(response)
		for _, leak := range []string{pkiTokenCanary, "PRIVATE KEY", "BEGIN", "refused"} {
			if strings.Contains(text, leak) {
				t.Errorf("status %d: diagnostic leaks %q: %s", status, leak, text)
			}
		}
		if !strings.Contains(text, "Unable to issue GoVault certificate") {
			t.Errorf("status %d: diagnostic = %q", status, text)
		}
		if fake.calls() != 1 {
			t.Errorf("status %d: calls = %d, a sign call must never be retried", status, fake.calls())
		}
	}
}

type failingSigner struct{ calls int }

func (s *failingSigner) SignCSR(context.Context, string, string, govaultclient.SignRequest) (govaultclient.SignedCertificate, error) {
	s.calls++
	return govaultclient.SignedCertificate{}, govaultclient.ErrRequestFailed
}

func TestPKICertificateOpenDoesNotRetryTransportFailures(t *testing.T) {
	t.Parallel()

	signer := &failingSigner{}
	if response, _ := openPKI(t, signer, nil); !response.Diagnostics.HasError() || signer.calls != 1 {
		t.Fatalf("calls = %d", signer.calls)
	}
}

func TestPKICertificateCloseKeepsTheClient(t *testing.T) {
	t.Parallel()

	signer := &failingSigner{}
	resource := &pkiCertificateEphemeralResource{client: signer}
	resource.Close(context.Background(), ephemeral.CloseRequest{}, &ephemeral.CloseResponse{})
	if resource.client != signer {
		t.Fatal("close cleared the shared client")
	}
}
