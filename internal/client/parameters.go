package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const (
	maxParameterBody = 4 << 20
	// parameterPageLimit is the largest page the server accepts.
	parameterPageLimit = 200
	// maxParameterPages bounds paging so a misbehaving server cannot loop the
	// provider; the server keeps at most 1000 live parameters per namespace.
	maxParameterPages = 50
)

// ErrNotFound reports that the server has no such parameter or version.
var ErrNotFound = errors.New("GoVault resource not found")

// Parameter is one version of a non-secret configuration value.
type Parameter struct {
	Name        string `json:"name"`
	Value       string `json:"value"`
	Description string `json:"description"`
	Version     int64  `json:"version"`
	Revision    string `json:"revision"`
	Created     int64  `json:"created"`
	Updated     int64  `json:"updated"`
	CreatedBy   string `json:"created_by"`
}

// ReadParameter reads the current version of a parameter, or a specific one when
// version is positive.
func (c *Client) ReadParameter(ctx context.Context, name string, version int64) (Parameter, error) {
	if strings.TrimSpace(name) == "" || version < 0 {
		return Parameter{}, ErrInvalidConfiguration
	}
	path, query := "/parameters/item", url.Values{"name": []string{name}}
	if version > 0 {
		path = "/parameters/item/versions/" + strconv.FormatInt(version, 10)
	}
	body, err := c.getParameterBody(ctx, path, query)
	if err != nil {
		return Parameter{}, err
	}
	var parameter Parameter
	if err := decodeOneJSON(body, &parameter); err != nil || !validParameter(parameter) {
		return Parameter{}, ErrInvalidResponse
	}
	return parameter, nil
}

// ListParameters returns every live parameter whose name starts with prefix,
// with its value, reading all pages. An empty prefix lists the namespace.
func (c *Client) ListParameters(ctx context.Context, prefix string) ([]Parameter, error) {
	var parameters []Parameter
	for page := 0; page < maxParameterPages; page++ {
		query := url.Values{"limit": []string{strconv.Itoa(parameterPageLimit)}, "offset": []string{strconv.Itoa(len(parameters))}}
		if prefix != "" {
			query.Set("prefix", prefix)
		}
		body, err := c.getParameterBody(ctx, "/parameters/summaries", query)
		if err != nil {
			return nil, err
		}
		var result struct {
			Parameters []Parameter `json:"parameters"`
			Total      int         `json:"total"`
		}
		if decodeOneJSON(body, &result) != nil || result.Total < 0 {
			return nil, ErrInvalidResponse
		}
		for _, parameter := range result.Parameters {
			if !validParameter(parameter) {
				return nil, ErrInvalidResponse
			}
		}
		parameters = append(parameters, result.Parameters...)
		if len(parameters) > result.Total || (len(result.Parameters) == 0 && len(parameters) < result.Total) {
			return nil, ErrInvalidResponse
		}
		if len(parameters) == result.Total {
			return parameters, nil
		}
	}
	return nil, ErrInvalidResponse
}

func validParameter(parameter Parameter) bool {
	// An empty value is valid: a parameter may be set to nothing.
	return parameter.Name != "" && parameter.Version > 0
}

func (c *Client) getParameterBody(ctx context.Context, path string, query url.Values) ([]byte, error) {
	c.mu.RLock()
	token, namespace := c.token, c.namespace
	c.mu.RUnlock()
	if namespace == "" {
		return nil, ErrInvalidConfiguration
	}
	requestURL := c.baseURL + "/ns/" + url.PathEscape(namespace) + path + "?" + query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, ErrRequestFailed
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/json")
	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, sanitizedRequestError(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, parameterStatusError(response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxParameterBody+1))
	if err != nil || len(body) > maxParameterBody {
		return nil, ErrInvalidResponse
	}
	return body, nil
}

// parameterStatusError maps a failure status to a stable error class. The
// response body is never read into the error.
func parameterStatusError(status int) error {
	switch status {
	case http.StatusBadRequest:
		return ErrInvalidRequest
	case http.StatusUnauthorized:
		return ErrUnauthorized
	case http.StatusForbidden:
		return ErrForbidden
	case http.StatusNotFound:
		return ErrNotFound
	case http.StatusTooManyRequests:
		return ErrRateLimited
	case http.StatusServiceUnavailable:
		return ErrServiceUnavailable
	}
	return fmt.Errorf("%w: HTTP %d", ErrUnexpectedStatus, status)
}
