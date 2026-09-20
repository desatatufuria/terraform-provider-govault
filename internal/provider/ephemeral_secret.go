package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ ephemeral.EphemeralResource              = (*secretEphemeralResource)(nil)
	_ ephemeral.EphemeralResourceWithConfigure = (*secretEphemeralResource)(nil)
	_ ephemeral.EphemeralResourceWithClose     = (*secretEphemeralResource)(nil)
)

type secretEphemeralResource struct{ client secretReader }

type secretEphemeralModel struct {
	Path            types.String `tfsdk:"path"`
	Version         types.Int64  `tfsdk:"version"`
	Value           types.String `tfsdk:"value"`
	ResolvedVersion types.Int64  `tfsdk:"resolved_version"`
}

func newSecretEphemeralResource() ephemeral.EphemeralResource { return &secretEphemeralResource{} }

func (r *secretEphemeralResource) Metadata(_ context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_secret"
}

func (r *secretEphemeralResource) Schema(_ context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Read one GoVault secret without storing it in Terraform state.",
		Attributes: map[string]schema.Attribute{
			"path":             schema.StringAttribute{Required: true, Description: "Slash-delimited secret path.", Validators: []validator.String{stringvalidator.LengthAtLeast(1)}},
			"version":          schema.Int64Attribute{Optional: true, Description: "Optional positive secret version; omit for latest.", Validators: []validator.Int64{int64validator.AtLeast(1)}},
			"value":            schema.StringAttribute{Computed: true, Sensitive: true, Description: "Ephemeral secret value."},
			"resolved_version": schema.Int64Attribute{Computed: true, Sensitive: true, Description: "Version returned by GoVault."},
		},
	}
}

func (r *secretEphemeralResource) Configure(_ context.Context, req ephemeral.ConfigureRequest, resp *ephemeral.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(secretReader)
	if !ok {
		resp.Diagnostics.AddError("Invalid GoVault client", "The provider supplied unexpected ephemeral resource data.")
		return
	}
	r.client = client
}

func (r *secretEphemeralResource) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("GoVault client unavailable", "Configure the provider before opening govault_secret.")
		return
	}
	var config secretEphemeralModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	version := int64(0)
	if config.Version.IsUnknown() {
		resp.Diagnostics.AddError("Unknown secret version", "The secret version must be known before govault_secret can be opened.")
		return
	}
	if !config.Version.IsNull() {
		version = config.Version.ValueInt64()
	}
	secret, err := r.client.ReadSecret(ctx, config.Path.ValueString(), version)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read GoVault secret", err.Error())
		return
	}
	if version > 0 && secret.Version != version {
		resp.Diagnostics.AddError("Unexpected GoVault secret version", "GoVault returned a different secret version than requested.")
		return
	}
	config.Value = types.StringValue(secret.Value)
	config.ResolvedVersion = types.Int64Value(secret.Version)
	resp.Diagnostics.Append(resp.Result.Set(ctx, &config)...)
}

func (*secretEphemeralResource) Close(context.Context, ephemeral.CloseRequest, *ephemeral.CloseResponse) {
}
