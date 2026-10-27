package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource              = (*parameterDataSource)(nil)
	_ datasource.DataSourceWithConfigure = (*parameterDataSource)(nil)
)

type parameterDataSource struct{ client parameterReader }

type parameterModel struct {
	Name        types.String `tfsdk:"name"`
	Version     types.Int64  `tfsdk:"version"`
	Value       types.String `tfsdk:"value"`
	Description types.String `tfsdk:"description"`
	Revision    types.String `tfsdk:"revision"`
	CreatedAt   types.String `tfsdk:"created_at"`
	UpdatedAt   types.String `tfsdk:"updated_at"`
	CreatedBy   types.String `tfsdk:"created_by"`
}

func newParameterDataSource() datasource.DataSource { return &parameterDataSource{} }

func (d *parameterDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_parameter"
}

func (d *parameterDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description:         "Read one GoVault parameter (non-secret configuration value).",
		MarkdownDescription: "Read one GoVault parameter by name, optionally at a specific version. " + parameterNotice,
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{Required: true, Description: "Slash-delimited parameter name in the namespace of the provider session.", Validators: []validator.String{stringvalidator.LengthAtLeast(1)}},
			"version": schema.Int64Attribute{
				Optional: true, Computed: true, Validators: []validator.Int64{int64validator.AtLeast(1)},
				Description: "Optional positive version to read; omit for the current version. Always set to the version that was read.",
			},
			"value":       schema.StringAttribute{Computed: true, Description: "Parameter value. Not sensitive: it is stored in clear in Terraform state."},
			"description": schema.StringAttribute{Computed: true, Description: "Description of this version; empty when none was written."},
			"revision":    schema.StringAttribute{Computed: true, Description: "Opaque revision identifier of this version."},
			"created_at":  schema.StringAttribute{Computed: true, Description: "RFC 3339 UTC time this version was created."},
			"updated_at":  schema.StringAttribute{Computed: true, Description: "RFC 3339 UTC time this version was last updated."},
			"created_by":  schema.StringAttribute{Computed: true, Description: "Identity that wrote this version; empty when not recorded."},
		},
	}
}

func (d *parameterDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if client, ok := configureParameterReader(req.ProviderData, &resp.Diagnostics); ok && client != nil {
		d.client = client
	}
}

func (d *parameterDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	if d.client == nil {
		resp.Diagnostics.AddError("GoVault client unavailable", "Configure the provider before reading govault_parameter.")
		return
	}
	var model parameterModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &model)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if model.Name.IsUnknown() || model.Version.IsUnknown() {
		resp.Diagnostics.AddError("Unknown parameter selector", "The parameter name and version must be known before govault_parameter can be read.")
		return
	}
	version := int64(0)
	if !model.Version.IsNull() {
		version = model.Version.ValueInt64()
	}
	parameter, err := d.client.ReadParameter(ctx, model.Name.ValueString(), version)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read GoVault parameter", parameterFailureDetail(err))
		return
	}
	if parameter.Name != model.Name.ValueString() || (version > 0 && parameter.Version != version) {
		resp.Diagnostics.AddError("Unexpected GoVault parameter", "GoVault returned a different parameter or version than requested.")
		return
	}
	model.Version = types.Int64Value(parameter.Version)
	model.Value = types.StringValue(parameter.Value)
	model.Description = types.StringValue(parameter.Description)
	model.Revision = types.StringValue(parameter.Revision)
	model.CreatedAt = unixTime(parameter.Created)
	model.UpdatedAt = unixTime(parameter.Updated)
	model.CreatedBy = types.StringValue(parameter.CreatedBy)
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}
