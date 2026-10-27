package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource              = (*parametersDataSource)(nil)
	_ datasource.DataSourceWithConfigure = (*parametersDataSource)(nil)
)

type parametersDataSource struct{ client parameterReader }

type parametersModel struct {
	Prefix     types.String `tfsdk:"prefix"`
	Values     types.Map    `tfsdk:"values"`
	Parameters types.List   `tfsdk:"parameters"`
}

var parameterItemTypes = map[string]attr.Type{
	"name": types.StringType, "value": types.StringType, "version": types.Int64Type, "description": types.StringType,
	"revision": types.StringType, "created_at": types.StringType, "updated_at": types.StringType, "created_by": types.StringType,
}

func newParametersDataSource() datasource.DataSource { return &parametersDataSource{} }

func (d *parametersDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_parameters"
}

func (d *parametersDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Read every GoVault parameter whose name starts with a prefix.",
		MarkdownDescription: "Read every GoVault parameter whose name starts with a prefix (all parameters when omitted). " +
			"Paging is handled by the provider. " + parameterNotice,
		Attributes: map[string]schema.Attribute{
			"prefix": schema.StringAttribute{
				Optional: true, Description: "Only parameters whose name starts with this prefix, for example `app/`. The identity needs list access on it.",
				Validators: []validator.String{stringvalidator.LengthAtMost(200)},
			},
			"values": schema.MapAttribute{Computed: true, ElementType: types.StringType, Description: "Map of parameter name to current value. Not sensitive."},
			"parameters": schema.ListNestedAttribute{
				Computed: true, Description: "Details of each parameter, ordered by name.",
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"name":        schema.StringAttribute{Computed: true, Description: "Parameter name."},
					"value":       schema.StringAttribute{Computed: true, Description: "Current value. Not sensitive."},
					"version":     schema.Int64Attribute{Computed: true, Description: "Current version."},
					"description": schema.StringAttribute{Computed: true, Description: "Description of the current version; empty when none."},
					"revision":    schema.StringAttribute{Computed: true, Description: "Opaque revision identifier of the current version."},
					"created_at":  schema.StringAttribute{Computed: true, Description: "RFC 3339 UTC time the current version was created."},
					"updated_at":  schema.StringAttribute{Computed: true, Description: "RFC 3339 UTC time the current version was last updated."},
					"created_by":  schema.StringAttribute{Computed: true, Description: "Identity that wrote the current version; empty when not recorded."},
				}},
			},
		},
	}
}

func (d *parametersDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if client, ok := configureParameterReader(req.ProviderData, &resp.Diagnostics); ok && client != nil {
		d.client = client
	}
}

func (d *parametersDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	if d.client == nil {
		resp.Diagnostics.AddError("GoVault client unavailable", "Configure the provider before reading govault_parameters.")
		return
	}
	var model parametersModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &model)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if model.Prefix.IsUnknown() {
		resp.Diagnostics.AddError("Unknown parameter prefix", "The prefix must be known before govault_parameters can be read.")
		return
	}
	parameters, err := d.client.ListParameters(ctx, model.Prefix.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Unable to list GoVault parameters", parameterFailureDetail(err))
		return
	}
	values := make(map[string]attr.Value, len(parameters))
	items := make([]attr.Value, 0, len(parameters))
	for _, parameter := range parameters {
		values[parameter.Name] = types.StringValue(parameter.Value)
		item, diagnostics := types.ObjectValue(parameterItemTypes, map[string]attr.Value{
			"name": types.StringValue(parameter.Name), "value": types.StringValue(parameter.Value), "version": types.Int64Value(parameter.Version),
			"description": types.StringValue(parameter.Description), "revision": types.StringValue(parameter.Revision),
			"created_at": unixTime(parameter.Created), "updated_at": unixTime(parameter.Updated), "created_by": types.StringValue(parameter.CreatedBy),
		})
		resp.Diagnostics.Append(diagnostics...)
		items = append(items, item)
	}
	valuesMap, mapDiagnostics := types.MapValue(types.StringType, values)
	resp.Diagnostics.Append(mapDiagnostics...)
	itemList, listDiagnostics := types.ListValue(types.ObjectType{AttrTypes: parameterItemTypes}, items)
	resp.Diagnostics.Append(listDiagnostics...)
	model.Values, model.Parameters = valuesMap, itemList
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}
