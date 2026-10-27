package provider

import (
	"context"
	"errors"
	"time"

	govaultclient "github.com/desatatufuria/terraform-provider-govault/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// parameterNotice is repeated in both data source descriptions and in the docs:
// a parameter value is stored in Terraform state in clear on purpose.
const parameterNotice = "Parameters are for **non-secret configuration** only. " +
	"Their values are NOT sensitive: they appear in plan output and are stored in clear in Terraform state. " +
	"Use the `govault_secret` ephemeral resource for secrets. " +
	"Managing parameters from Terraform is not offered; this provider reads them only."

type parameterReader interface {
	ReadParameter(context.Context, string, int64) (govaultclient.Parameter, error)
	ListParameters(context.Context, string) ([]govaultclient.Parameter, error)
}

// govaultAPI is everything the configured provider session can do.
type govaultAPI interface {
	secretReader
	parameterReader
}

func configureParameterReader(providerData any, diagnostics *diag.Diagnostics) (parameterReader, bool) {
	if providerData == nil {
		return nil, true
	}
	reader, ok := providerData.(parameterReader)
	if !ok {
		diagnostics.AddError("Invalid GoVault client", "The provider supplied unexpected data source data.")
	}
	return reader, ok
}

// parameterFailureDetail turns a client error class into an actionable message.
// It adds no response body and no credential; err itself carries only a class.
func parameterFailureDetail(err error) string {
	switch {
	case errors.Is(err, govaultclient.ErrNotFound):
		return "The parameter (or the requested version) does not exist in the namespace of this session. " + err.Error()
	case errors.Is(err, govaultclient.ErrForbidden):
		return "The authenticated identity is not allowed to read this parameter or list this prefix. " + err.Error()
	case errors.Is(err, govaultclient.ErrUnauthorized):
		return "GoVault rejected the session. Authenticate again and retry. " + err.Error()
	case errors.Is(err, govaultclient.ErrServiceUnavailable):
		return "GoVault is unavailable; the vault may be sealed. Unseal it or retry later. " + err.Error()
	case errors.Is(err, govaultclient.ErrRateLimited):
		return "GoVault rate limit reached. Retry later or reduce the number of parameter reads. " + err.Error()
	}
	return err.Error()
}

func unixTime(seconds int64) types.String {
	if seconds <= 0 {
		return types.StringValue("")
	}
	return types.StringValue(time.Unix(seconds, 0).UTC().Format(time.RFC3339))
}
