package provider

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func parametersRead(t *testing.T, source *parametersDataSource, prefix any) (parametersModel, datasource.ReadResponse) {
	t.Helper()
	var schemaResponse datasource.SchemaResponse
	source.Schema(context.Background(), datasource.SchemaRequest{}, &schemaResponse)
	s := schemaResponse.Schema
	itemType := s.Attributes["parameters"].GetType().(attr.TypeWithElementType).ElementType().TerraformType(context.Background())
	raw := tftypes.NewValue(s.Type().TerraformType(context.Background()), map[string]tftypes.Value{
		"prefix":     tftypes.NewValue(tftypes.String, prefix),
		"values":     tftypes.NewValue(tftypes.Map{ElementType: tftypes.String}, nil),
		"parameters": tftypes.NewValue(tftypes.List{ElementType: itemType}, nil),
	})
	config := tfsdk.Config{Schema: s, Raw: raw}
	response := datasource.ReadResponse{State: tfsdk.State{Schema: s, Raw: raw}}
	source.Read(context.Background(), datasource.ReadRequest{Config: config}, &response)
	var model parametersModel
	if !response.Diagnostics.HasError() {
		if d := response.State.Get(context.Background(), &model); d.HasError() {
			t.Fatalf("state: %v", d)
		}
	}
	return model, response
}

func TestParametersDataSourceSchema(t *testing.T) {
	source := &parametersDataSource{}
	var schemaResponse datasource.SchemaResponse
	source.Schema(context.Background(), datasource.SchemaRequest{}, &schemaResponse)
	if schemaResponse.Diagnostics.HasError() {
		t.Fatalf("schema diagnostics: %v", schemaResponse.Diagnostics)
	}
	var s schema.Schema = schemaResponse.Schema
	if !s.Attributes["prefix"].IsOptional() || !s.Attributes["values"].IsComputed() || !s.Attributes["parameters"].IsComputed() {
		t.Error("prefix must be optional; values and parameters computed")
	}
	if s.Attributes["values"].IsSensitive() || s.Attributes["parameters"].IsSensitive() {
		t.Error("parameters are non-secret by design and must not be sensitive")
	}
	if !strings.Contains(s.MarkdownDescription, "non-secret") {
		t.Error("the description must warn that parameters are for non-secret configuration")
	}
	var configureResponse datasource.ConfigureResponse
	source.Configure(context.Background(), datasource.ConfigureRequest{ProviderData: "wrong"}, &configureResponse)
	if !configureResponse.Diagnostics.HasError() {
		t.Fatal("wrong provider data must fail")
	}
}

func TestParametersDataSourceReadsPrefix(t *testing.T) {
	source := &parametersDataSource{client: parameterTestServer(t)}
	model, response := parametersRead(t, source, "app/")
	if response.Diagnostics.HasError() {
		t.Fatalf("diagnostics: %v", response.Diagnostics)
	}
	values := model.Values.Elements()
	if len(values) != 2 || values["app/log-level"] != types.StringValue("debug") || values["app/region"] != types.StringValue("eu") {
		t.Fatalf("values = %v", values)
	}
	items := model.Parameters.Elements()
	if len(items) != 2 {
		t.Fatalf("parameters = %v", items)
	}
	second, ok := items[1].(types.Object)
	if !ok || second.Attributes()["name"] != types.StringValue("app/region") || second.Attributes()["version"] != types.Int64Value(1) ||
		second.Attributes()["description"] != types.StringValue("d") {
		t.Fatalf("second item = %v", items[1])
	}
}

func TestParametersDataSourceFailureDiagnostics(t *testing.T) {
	source := &parametersDataSource{client: parameterTestServer(t)}
	_, response := parametersRead(t, source, "denied/")
	if !response.Diagnostics.HasError() || !strings.Contains(fmt.Sprint(response.Diagnostics), "not allowed") ||
		strings.Contains(fmt.Sprint(response.Diagnostics), parameterTokenCanary) {
		t.Fatalf("diagnostics = %v", response.Diagnostics)
	}
	_, response = parametersRead(t, source, tftypes.UnknownValue)
	if !response.Diagnostics.HasError() {
		t.Fatal("unknown prefix must fail")
	}
	var unconfigured datasource.ReadResponse
	(&parametersDataSource{}).Read(context.Background(), datasource.ReadRequest{}, &unconfigured)
	if !unconfigured.Diagnostics.HasError() {
		t.Fatal("read without client must fail")
	}
}
