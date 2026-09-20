package provider

import (
	"context"
	"errors"
	"os"
	"strings"

	govaultclient "github.com/desatatufuria/terraform-provider-govault/internal/client"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
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
	tokenAuth       = "token"
	workloadAuth    = "workload"
)

var (
	_ provider.Provider                       = (*goVaultProvider)(nil)
	_ provider.ProviderWithEphemeralResources = (*goVaultProvider)(nil)
)

type goVaultProvider struct {
	version   string
	lookupEnv func(string) (string, bool)
}

type providerModel struct {
	Address               types.String `tfsdk:"address"`
	AuthMethod            types.String `tfsdk:"auth_method"`
	TokenEnv              types.String `tfsdk:"token_env"`
	WorkloadRoleRef       types.String `tfsdk:"workload_role_ref"`
	WorkloadAssertionEnv  types.String `tfsdk:"workload_assertion_env"`
	WorkloadAssertionFile types.String `tfsdk:"workload_assertion_file"`
	CACertFile            types.String `tfsdk:"ca_cert_file"`
}

// New returns a provider factory for Terraform protocol servers and tests.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &goVaultProvider{version: version, lookupEnv: os.LookupEnv}
	}
}

func (p *goVaultProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "govault"
	resp.Version = p.version
}

func (p *goVaultProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Configure the GoVault provider with token bootstrap, verified TLS, and server-derived namespace authority.",
		Attributes: map[string]schema.Attribute{
			"address": schema.StringAttribute{
				Description: "Base HTTPS address of the GoVault API.",
				Required:    true,
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"auth_method": schema.StringAttribute{
				Description: "Explicit authentication method: token or workload.",
				Required:    true,
				Validators: []validator.String{
					stringvalidator.OneOf(tokenAuth, workloadAuth),
				},
			},
			"token_env": schema.StringAttribute{
				Description: "Name of the environment variable that will supply the GoVault token. This is a selector, not the token value.",
				Optional:    true,
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"workload_role_ref":       schema.StringAttribute{Optional: true, Description: "GoVault workload authentication role reference."},
			"workload_assertion_env":  schema.StringAttribute{Optional: true, Description: "Name of the environment variable supplying the workload assertion."},
			"workload_assertion_file": schema.StringAttribute{Optional: true, Description: "Path to a protected file supplying the workload assertion."},
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
	if resp.Diagnostics.HasError() {
		return
	}

	lookupEnv := p.lookupEnv
	if lookupEnv == nil {
		lookupEnv = os.LookupEnv
	}
	configuredClient := p.configureClient(ctx, config, lookupEnv, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.EphemeralResourceData = configuredClient
}

func (p *goVaultProvider) configureClient(ctx context.Context, config providerModel, lookupEnv func(string) (string, bool), diagnostics *diag.Diagnostics) secretReader {
	method := config.AuthMethod.ValueString()
	if method != tokenAuth && method != workloadAuth {
		diagnostics.AddError("Unsupported authentication method", "The provider auth_method must be either \"token\" or \"workload\".")
		return nil
	}
	if method == tokenAuth {
		if !config.WorkloadRoleRef.IsNull() || !config.WorkloadAssertionEnv.IsNull() || !config.WorkloadAssertionFile.IsNull() {
			diagnostics.AddError("Invalid token authentication selectors", "Workload selectors cannot be configured when auth_method is token.")
			return nil
		}
		tokenEnv := defaultTokenEnv
		if !config.TokenEnv.IsNull() {
			tokenEnv = config.TokenEnv.ValueString()
		}
		if strings.TrimSpace(tokenEnv) == "" {
			diagnostics.AddError("Missing token environment selector", "The provider token_env must name exactly one environment variable.")
			return nil
		}
		token, ok := lookupEnv(tokenEnv)
		if !ok || strings.TrimSpace(token) == "" {
			diagnostics.AddError("Missing GoVault token", "The environment variable selected by token_env is not set or is empty.")
			return nil
		}
		client, err := govaultclient.New(govaultclient.Config{Address: config.Address.ValueString(), Token: token, CACertFile: config.CACertFile.ValueString()})
		if err != nil {
			diagnostics.AddError("Invalid GoVault client configuration", err.Error())
			return nil
		}
		if err := client.Authenticate(ctx); err != nil {
			diagnostics.AddError("GoVault authentication failed", err.Error())
			return nil
		}
		return client
	}
	if !config.TokenEnv.IsNull() {
		diagnostics.AddError("Invalid workload authentication selectors", "token_env cannot be configured when auth_method is workload.")
		return nil
	}
	roleRef := config.WorkloadRoleRef.ValueString()
	if config.WorkloadRoleRef.IsNull() || strings.TrimSpace(roleRef) == "" {
		diagnostics.AddError("Missing workload role reference", "workload_role_ref must be configured and non-empty.")
		return nil
	}
	if config.WorkloadAssertionEnv.IsNull() == config.WorkloadAssertionFile.IsNull() {
		diagnostics.AddError("Invalid workload assertion source", "Configure exactly one workload assertion source.")
		return nil
	}
	client, err := govaultclient.NewProtocolClient(govaultclient.Config{Address: config.Address.ValueString(), CACertFile: config.CACertFile.ValueString()})
	if err != nil {
		diagnostics.AddError("Invalid GoVault client configuration", err.Error())
		return nil
	}
	session := newWorkloadSession(client, roleRef, func() (string, error) { return readWorkloadAssertion(config, lookupEnv) })
	if err := session.authenticate(ctx); err != nil {
		var sourceError assertionSourceError
		if errors.As(err, &sourceError) {
			diagnostics.AddError("Invalid workload assertion source", err.Error())
		} else {
			diagnostics.AddError("GoVault workload authentication failed", err.Error())
		}
		return nil
	}
	return session
}

func (p *goVaultProvider) DataSources(context.Context) []func() datasource.DataSource {
	return nil
}

func (p *goVaultProvider) Resources(context.Context) []func() resource.Resource {
	return nil
}

func (p *goVaultProvider) EphemeralResources(context.Context) []func() ephemeral.EphemeralResource {
	return []func() ephemeral.EphemeralResource{newSecretEphemeralResource}
}

func validateKnownConfiguration(config providerModel) diag.Diagnostics {
	values := map[string]attr.Value{
		"address":                 config.Address,
		"auth_method":             config.AuthMethod,
		"token_env":               config.TokenEnv,
		"workload_role_ref":       config.WorkloadRoleRef,
		"workload_assertion_env":  config.WorkloadAssertionEnv,
		"workload_assertion_file": config.WorkloadAssertionFile,
		"ca_cert_file":            config.CACertFile,
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
