package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

const (
	// RegistryAddress is the fully-qualified Terraform Registry provider address.
	RegistryAddress = "registry.terraform.io/desatatufuria/govault"
	defaultTokenEnv = "GOVAULT_TOKEN"
	supportedAuth   = "token"
)

var _ provider.Provider = (*goVaultProvider)(nil)

type goVaultProvider struct {
	version string
}

type providerModel struct {
	Address    types.String `tfsdk:"address"`
	AuthMethod types.String `tfsdk:"auth_method"`
	TokenEnv   types.String `tfsdk:"token_env"`
	CACertFile types.String `tfsdk:"ca_cert_file"`
}

// New returns a provider factory for Terraform protocol servers and tests.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &goVaultProvider{version: version}
	}
}

func (p *goVaultProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "govault"
	resp.Version = p.version
}

func (p *goVaultProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Configure the GoVault provider. This scaffold validates non-secret connection selectors offline and does not connect to GoVault yet.",
		Attributes: map[string]schema.Attribute{
			"address": schema.StringAttribute{
				Description: "Base HTTPS address of the GoVault API.",
				Required:    true,
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"auth_method": schema.StringAttribute{
				Description: "Authentication method. Phase E supports only token bootstrap.",
				Required:    true,
				Validators: []validator.String{
					stringvalidator.OneOf(supportedAuth),
				},
			},
			"token_env": schema.StringAttribute{
				Description: "Name of the environment variable that will supply the GoVault token. This is a selector, not the token value.",
				Optional:    true,
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"ca_cert_file": schema.StringAttribute{
				Description: "Optional path to a PEM-encoded CA certificate file used to verify GoVault.",
				Optional:    true,
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
		},
	}
}

func (p *goVaultProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(validateKnownConfiguration(config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if config.Address.IsNull() {
		resp.Diagnostics.AddError("Missing GoVault address", "The provider address must be configured.")
	}
	if config.AuthMethod.IsNull() {
		resp.Diagnostics.AddError("Missing authentication method", "The provider auth_method must be configured.")
		return
	}
	if config.AuthMethod.ValueString() != supportedAuth {
		resp.Diagnostics.AddError("Unsupported authentication method", "The provider currently supports only auth_method = \"token\".")
	}
	if config.TokenEnv.IsNull() {
		config.TokenEnv = types.StringValue(defaultTokenEnv)
	}

	// A null token_env selects defaultTokenEnv when PHE-002 constructs a client.
	// PHE-002 owns token lookup, TLS construction, and client configuration.
	// This scaffold intentionally leaves provider data unset and performs no I/O.
}

func (p *goVaultProvider) DataSources(context.Context) []func() datasource.DataSource {
	return nil
}

func (p *goVaultProvider) Resources(context.Context) []func() resource.Resource {
	return nil
}

func validateKnownConfiguration(config providerModel) diag.Diagnostics {
	values := map[string]attr.Value{
		"address":      config.Address,
		"auth_method":  config.AuthMethod,
		"token_env":    config.TokenEnv,
		"ca_cert_file": config.CACertFile,
	}

	var diagnostics diag.Diagnostics
	for name, value := range values {
		if value.IsUnknown() {
			diagnostics.AddError(
				"Unknown provider configuration",
				"The provider cannot be configured while "+name+" is unknown. Use a value that is available during provider configuration.",
			)
		}
	}
	return diagnostics
}
