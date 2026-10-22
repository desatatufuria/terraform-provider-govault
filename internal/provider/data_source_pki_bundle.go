package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource              = (*pkiBundleDataSource)(nil)
	_ datasource.DataSourceWithConfigure = (*pkiBundleDataSource)(nil)
)

type pkiBundleDataSource struct{ client bundleReader }

type pkiBundleModel struct {
	Namespace types.String `tfsdk:"namespace"`
	Issuer    types.String `tfsdk:"issuer"`
	ID        types.String `tfsdk:"id"`
	PEM       types.String `tfsdk:"pem"`
}

func newPKIBundleDataSource() datasource.DataSource { return &pkiBundleDataSource{} }

func (d *pkiBundleDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_pki_bundle"
}

func (d *pkiBundleDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Read the public CA certificates of a GoVault namespace (PEM). Public data: it holds certificates only, never a key, and is read from the unauthenticated public PKI routes.",
		Attributes: map[string]schema.Attribute{
			"namespace": schema.StringAttribute{Optional: true, Description: "GoVault namespace; defaults to the namespace of the authenticated session."},
			"issuer":    schema.StringAttribute{Optional: true, Description: "Id of one intermediate CA (gv.pki.ca.<id>); omit for the namespace bundle (active intermediate and root)."},
			"id":        schema.StringAttribute{Computed: true, Description: "The namespace, or namespace/issuer."},
			"pem":       schema.StringAttribute{Computed: true, Description: "CA certificate(s), PEM."},
		},
	}
}

func (d *pkiBundleDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(bundleReader)
	if !ok {
		resp.Diagnostics.AddError("Invalid GoVault client", "The provider supplied unexpected data source data.")
		return
	}
	d.client = client
}

func (d *pkiBundleDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	if d.client == nil {
		resp.Diagnostics.AddError("GoVault client unavailable", "Configure the provider before reading govault_pki_bundle.")
		return
	}
	var config pkiBundleModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if config.Namespace.IsUnknown() || config.Issuer.IsUnknown() {
		resp.Diagnostics.AddError("Unknown bundle input", "namespace and issuer must be known before govault_pki_bundle can be read.")
		return
	}
	var (
		pemText string
		err     error
	)
	if config.Issuer.IsNull() || config.Issuer.ValueString() == "" {
		pemText, err = d.client.PublicCABundle(ctx, config.Namespace.ValueString())
	} else {
		pemText, err = d.client.PublicIssuerCertificate(ctx, config.Namespace.ValueString(), config.Issuer.ValueString())
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read GoVault CA bundle", err.Error())
		return
	}
	id := config.Namespace.ValueString()
	if id == "" {
		id = "session"
	}
	if !config.Issuer.IsNull() && config.Issuer.ValueString() != "" {
		id += "/" + config.Issuer.ValueString()
	}
	config.ID, config.PEM = types.StringValue(id), types.StringValue(pemText)
	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
