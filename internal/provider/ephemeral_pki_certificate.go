package provider

import (
	"context"
	"regexp"
	"strings"
	"time"

	govaultclient "github.com/desatatufuria/terraform-provider-govault/internal/client"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ ephemeral.EphemeralResource                   = (*pkiCertificateEphemeralResource)(nil)
	_ ephemeral.EphemeralResourceWithConfigure      = (*pkiCertificateEphemeralResource)(nil)
	_ ephemeral.EphemeralResourceWithValidateConfig = (*pkiCertificateEphemeralResource)(nil)
	_ ephemeral.EphemeralResourceWithClose          = (*pkiCertificateEphemeralResource)(nil)
)

var namespacePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

type pkiCertificateEphemeralResource struct {
	client certificateSigner
	now    func() time.Time
}

type pkiCertificateModel struct {
	Namespace        types.String `tfsdk:"namespace"`
	Role             types.String `tfsdk:"role"`
	CommonName       types.String `tfsdk:"common_name"`
	AltNames         types.List   `tfsdk:"alt_names"`
	IPSANs           types.List   `tfsdk:"ip_sans"`
	URISANs          types.List   `tfsdk:"uri_sans"`
	EmailSANs        types.List   `tfsdk:"email_sans"`
	TTL              types.String `tfsdk:"ttl"`
	KeyType          types.String `tfsdk:"key_type"`
	Self             types.Bool   `tfsdk:"self"`
	ID               types.String `tfsdk:"id"`
	Certificate      types.String `tfsdk:"certificate"`
	PrivateKey       types.String `tfsdk:"private_key"`
	Chain            types.String `tfsdk:"chain"`
	CACertificate    types.String `tfsdk:"ca_certificate"`
	Serial           types.String `tfsdk:"serial"`
	NotBefore        types.String `tfsdk:"not_before"`
	NotAfter         types.String `tfsdk:"not_after"`
	ExpiresInSeconds types.Int64  `tfsdk:"expires_in_seconds"`
}

func newPKICertificateEphemeralResource() ephemeral.EphemeralResource {
	return &pkiCertificateEphemeralResource{}
}

func (r *pkiCertificateEphemeralResource) Metadata(_ context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_pki_certificate"
}

func (r *pkiCertificateEphemeralResource) Schema(_ context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	list := func(description string) schema.ListAttribute {
		return schema.ListAttribute{Optional: true, ElementType: types.StringType, Description: description}
	}
	resp.Schema = schema.Schema{
		Description: "Issue one GoVault PKI certificate without storing it, or its private key, in Terraform state. " +
			"The private key is generated inside the provider process and never sent to GoVault; only a certificate request is. " +
			"Every open issues a new certificate.",
		Attributes: map[string]schema.Attribute{
			"namespace":          schema.StringAttribute{Optional: true, Description: "GoVault namespace of the PKI role; defaults to the namespace of the authenticated session."},
			"role":               schema.StringAttribute{Required: true, Description: "Name of the PKI role that signs the certificate.", Validators: []validator.String{stringvalidator.LengthAtLeast(1)}},
			"common_name":        schema.StringAttribute{Optional: true, Description: "Subject common name. Required unless self is true."},
			"alt_names":          list("DNS subject alternative names."),
			"ip_sans":            list("IP address subject alternative names."),
			"uri_sans":           list("URI subject alternative names."),
			"email_sans":         list("E-mail subject alternative names."),
			"ttl":                schema.StringAttribute{Optional: true, Description: "Requested lifetime such as 90m, 24h or 7d; omit for the default of the role."},
			"key_type":           schema.StringAttribute{Optional: true, Description: "Key to generate locally: ecdsa-p256 (default), ecdsa-p384, rsa-2048 or rsa-4096.", Validators: []validator.String{stringvalidator.OneOf(supportedKeyTypes...)}},
			"self":               schema.BoolAttribute{Optional: true, Description: "Set for a self-issue profile role: no names are sent and GoVault builds the subject from the authenticated identity. Cannot be combined with common_name or any *_sans/alt_names."},
			"id":                 schema.StringAttribute{Computed: true, Description: "GoVault certificate record id; use it to revoke the certificate."},
			"certificate":        schema.StringAttribute{Computed: true, Description: "Leaf certificate, PEM."},
			"private_key":        schema.StringAttribute{Computed: true, Sensitive: true, Description: "Private key, PKCS#8 PEM, generated locally. Pass it only to write-only or ephemeral-capable destinations."},
			"chain":              schema.StringAttribute{Computed: true, Description: "Issuing chain up to the root, PEM."},
			"ca_certificate":     schema.StringAttribute{Computed: true, Description: "Issuing intermediate CA certificate, PEM."},
			"serial":             schema.StringAttribute{Computed: true, Description: "Certificate serial number."},
			"not_before":         schema.StringAttribute{Computed: true, Description: "Start of validity, RFC 3339 UTC."},
			"not_after":          schema.StringAttribute{Computed: true, Description: "End of validity, RFC 3339 UTC."},
			"expires_in_seconds": schema.Int64Attribute{Computed: true, Description: "Seconds of validity left when the certificate was issued."},
		},
	}
}

func (r *pkiCertificateEphemeralResource) Configure(_ context.Context, req ephemeral.ConfigureRequest, resp *ephemeral.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(certificateSigner)
	if !ok {
		resp.Diagnostics.AddError("Invalid GoVault client", "The provider supplied unexpected ephemeral resource data.")
		return
	}
	r.client = client
}

// ValidateConfig refuses what is already wrong at plan time, using only the
// values that are known then. Open runs the same checks again on known values.
func (r *pkiCertificateEphemeralResource) ValidateConfig(ctx context.Context, req ephemeral.ValidateConfigRequest, resp *ephemeral.ValidateConfigResponse) {
	var config pkiCertificateModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(validateCertificateConfig(config)...)
}

func (r *pkiCertificateEphemeralResource) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("GoVault client unavailable", "Configure the provider before opening govault_pki_certificate.")
		return
	}
	var config pkiCertificateModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if config.hasUnknownInput() {
		resp.Diagnostics.AddError("Unknown certificate input", "Every govault_pki_certificate input must be known before the certificate can be issued.")
		return
	}
	resp.Diagnostics.Append(validateCertificateConfig(config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	names := certificateNames{CommonName: strings.TrimSpace(config.CommonName.ValueString())}
	if !config.Self.ValueBool() {
		names.DNS, names.IPs, names.URIs, names.Emails = listValues(config.AltNames), listValues(config.IPSANs), listValues(config.URISANs), listValues(config.EmailSANs)
	}
	ttl, err := parseTTLSeconds(config.TTL.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Invalid certificate ttl", err.Error())
		return
	}
	key, err := generatePKIKey(config.KeyType.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Unable to generate the private key", err.Error())
		return
	}
	csr, err := buildCSR(names, key)
	if err != nil {
		resp.Diagnostics.AddError("Invalid certificate request", err.Error())
		return
	}
	// Exactly one sign call: it issues a certificate every time, so it is never retried.
	signed, err := r.client.SignCSR(ctx, config.Namespace.ValueString(), config.Role.ValueString(), govaultclient.SignRequest{CSRPEM: csr, CommonName: names.CommonName, TTLSeconds: ttl})
	if err != nil {
		resp.Diagnostics.AddError("Unable to issue GoVault certificate", err.Error())
		return
	}
	cert, err := certificateMatchingKey(signed.CertificatePEM, key)
	if err != nil {
		resp.Diagnostics.AddError("Unexpected GoVault certificate", err.Error())
		return
	}
	privateKey, err := encodePKIKey(key)
	if err != nil {
		resp.Diagnostics.AddError("Unable to encode the private key", err.Error())
		return
	}
	now := time.Now
	if r.now != nil {
		now = r.now
	}
	chain := signed.CAChainPEM
	if chain == "" {
		chain = signed.IssuingCAPEM
	}
	config.ID = types.StringValue(signed.ID)
	config.Certificate = types.StringValue(signed.CertificatePEM)
	config.PrivateKey = types.StringValue(privateKey)
	config.Chain = types.StringValue(chain)
	config.CACertificate = types.StringValue(signed.IssuingCAPEM)
	config.Serial = types.StringValue(signed.SerialNumber)
	config.NotBefore = types.StringValue(cert.NotBefore.UTC().Format(time.RFC3339))
	config.NotAfter = types.StringValue(cert.NotAfter.UTC().Format(time.RFC3339))
	config.ExpiresInSeconds = types.Int64Value(max(0, int64(cert.NotAfter.Sub(now()).Seconds())))
	resp.Diagnostics.Append(resp.Result.Set(ctx, &config)...)
}

// Close keeps the shared configured client; nothing per certificate is held.
// There is no Renew: an ephemeral result cannot change after Open, so a renewal
// could not hand a new certificate to its consumers. Each open issues a new one.
func (*pkiCertificateEphemeralResource) Close(context.Context, ephemeral.CloseRequest, *ephemeral.CloseResponse) {
}

func (m pkiCertificateModel) hasUnknownInput() bool {
	return m.Namespace.IsUnknown() || m.Role.IsUnknown() || m.CommonName.IsUnknown() || m.AltNames.IsUnknown() || m.IPSANs.IsUnknown() ||
		m.URISANs.IsUnknown() || m.EmailSANs.IsUnknown() || m.TTL.IsUnknown() || m.KeyType.IsUnknown() || m.Self.IsUnknown() ||
		listHasUnknown(m.AltNames) || listHasUnknown(m.IPSANs) || listHasUnknown(m.URISANs) || listHasUnknown(m.EmailSANs)
}

func listHasUnknown(list types.List) bool {
	for _, element := range list.Elements() {
		if element.IsUnknown() {
			return true
		}
	}
	return false
}

// listValues returns the known, trimmed, non-empty strings of a list.
func listValues(list types.List) []string {
	var values []string
	for _, element := range list.Elements() {
		if text, ok := element.(types.String); ok && !text.IsNull() && !text.IsUnknown() {
			if trimmed := strings.TrimSpace(text.ValueString()); trimmed != "" {
				values = append(values, trimmed)
			}
		}
	}
	return values
}

// validateCertificateConfig checks the known values only; unknown ones are
// checked again when the resource is opened.
func validateCertificateConfig(config pkiCertificateModel) diag.Diagnostics {
	var diagnostics diag.Diagnostics
	if known(config.Namespace) && !config.Namespace.IsNull() && !namespacePattern.MatchString(config.Namespace.ValueString()) {
		diagnostics.AddAttributeError(path.Root("namespace"), "Invalid namespace", "namespace must be a lowercase GoVault namespace name.")
	}
	if known(config.KeyType) && !config.KeyType.IsNull() && !isSupportedKeyType(config.KeyType.ValueString()) {
		diagnostics.AddAttributeError(path.Root("key_type"), "Invalid key_type", "key_type must be one of: "+strings.Join(supportedKeyTypes, ", ")+".")
	}
	if known(config.TTL) && !config.TTL.IsNull() {
		if _, err := parseTTLSeconds(config.TTL.ValueString()); err != nil {
			diagnostics.AddAttributeError(path.Root("ttl"), "Invalid ttl", err.Error())
		}
	}
	if config.Self.IsUnknown() {
		return diagnostics
	}
	if config.Self.ValueBool() {
		anyName := (known(config.CommonName) && strings.TrimSpace(config.CommonName.ValueString()) != "") ||
			len(listValues(config.AltNames))+len(listValues(config.IPSANs))+len(listValues(config.URISANs))+len(listValues(config.EmailSANs)) > 0
		if anyName {
			diagnostics.AddAttributeError(path.Root("self"), "Conflicting self and names",
				"self sends no names: remove common_name, alt_names, ip_sans, uri_sans and email_sans; the role builds them from the authenticated identity.")
		}
	} else if known(config.CommonName) && strings.TrimSpace(config.CommonName.ValueString()) == "" {
		diagnostics.AddAttributeError(path.Root("common_name"), "Missing common_name", "common_name is required unless self is true.")
	}
	return diagnostics
}

func known(value types.String) bool { return !value.IsUnknown() }
