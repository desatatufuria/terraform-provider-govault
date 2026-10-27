package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestReadParameterCurrentAndSpecificVersion(t *testing.T) {
	t.Parallel()
	var paths []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.EscapedPath())
		if r.Header.Get("Authorization") != "Bearer gv.token" || r.URL.Query().Get("name") != "app/log-level" {
			t.Errorf("unexpected request: %s", r.URL.String())
		}
		_, _ = w.Write([]byte(`{"name":"app/log-level","value":"","description":"d","version":3,"revision":"gv.prev.x","created":10,"updated":20,"created_by":"alice"}`))
	}))
	defer server.Close()
	client := newTestClient(t, server, server.URL, "gv.token", time.Second)
	client.namespace = "team a"

	parameter, err := client.ReadParameter(context.Background(), "app/log-level", 0)
	if err != nil || parameter.Version != 3 || parameter.Value != "" || parameter.Updated != 20 || parameter.CreatedBy != "alice" {
		t.Fatalf("parameter = %#v, error = %v", parameter, err)
	}
	if _, err := client.ReadParameter(context.Background(), "app/log-level", 2); err != nil {
		t.Fatal(err)
	}
	want := "/ns/team%20a/parameters/item,/ns/team%20a/parameters/item/versions/2"
	if got := strings.Join(paths, ","); got != want {
		t.Fatalf("paths = %s, want %s", got, want)
	}
}

func TestReadParameterClassifiesFailuresWithoutLeaks(t *testing.T) {
	t.Parallel()
	const canary = "parameter-body-canary"
	tests := map[string]struct {
		status int
		body   string
		want   error
	}{
		"unauthorized": {http.StatusUnauthorized, canary, ErrUnauthorized},
		"forbidden":    {http.StatusForbidden, canary, ErrForbidden},
		"not found":    {http.StatusNotFound, canary, ErrNotFound},
		"sealed":       {http.StatusServiceUnavailable, canary, ErrServiceUnavailable},
		"rate limited": {http.StatusTooManyRequests, canary, ErrRateLimited},
		"bad request":  {http.StatusBadRequest, canary, ErrInvalidRequest},
		"status":       {http.StatusInternalServerError, canary, ErrUnexpectedStatus},
		"no name":      {http.StatusOK, `{"value":"x","version":1}`, ErrInvalidResponse},
		"bad version":  {http.StatusOK, `{"name":"a","value":"x","version":0}`, ErrInvalidResponse},
		"trailing":     {http.StatusOK, `{"name":"a","value":"x","version":1}` + canary, ErrInvalidResponse},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			client := newTestClient(t, server, server.URL, "gv.token", time.Second)
			client.namespace = "team-a"
			_, err := client.ReadParameter(context.Background(), "a", 0)
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			assertRedacted(t, err, canary)
			assertRedacted(t, err, "gv.token")
		})
	}
}

func TestReadParameterRejectsInvalidInput(t *testing.T) {
	t.Parallel()
	client := &Client{namespace: "team-a"}
	if _, err := client.ReadParameter(context.Background(), " ", 0); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("blank name error = %v", err)
	}
	if _, err := client.ReadParameter(context.Background(), "a", -1); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("negative version error = %v", err)
	}
	if _, err := (&Client{}).ReadParameter(context.Background(), "a", 0); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("no namespace error = %v", err)
	}
}

func TestListParametersPagesUntilTotal(t *testing.T) {
	t.Parallel()
	var offsets []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ns/team-a/parameters/summaries" || r.URL.Query().Get("prefix") != "app/" || r.URL.Query().Get("limit") != "200" {
			t.Errorf("unexpected request: %s", r.URL.String())
		}
		offset := r.URL.Query().Get("offset")
		offsets = append(offsets, offset)
		switch offset {
		case "0":
			_, _ = w.Write([]byte(`{"parameters":[{"name":"app/a","value":"1","version":1},{"name":"app/b","value":"2","version":4}],"total":3}`))
		case "2":
			_, _ = w.Write([]byte(`{"parameters":[{"name":"app/c","value":"3","version":1}],"total":3}`))
		default:
			t.Errorf("unexpected offset %q", offset)
		}
	}))
	defer server.Close()
	client := newTestClient(t, server, server.URL, "gv.token", time.Second)
	client.namespace = "team-a"

	parameters, err := client.ListParameters(context.Background(), "app/")
	if err != nil || len(parameters) != 3 || parameters[2].Name != "app/c" || parameters[1].Version != 4 {
		t.Fatalf("parameters = %#v, error = %v", parameters, err)
	}
	if strings.Join(offsets, ",") != "0,2" {
		t.Fatalf("offsets = %v", offsets)
	}
}

func TestListParametersFailsClosed(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		status int
		body   string
		want   error
	}{
		"forbidden":   {http.StatusForbidden, "", ErrForbidden},
		"sealed":      {http.StatusServiceUnavailable, "", ErrServiceUnavailable},
		"empty page":  {http.StatusOK, `{"parameters":[],"total":5}`, ErrInvalidResponse},
		"invalid row": {http.StatusOK, `{"parameters":[{"name":"","version":1}],"total":1}`, ErrInvalidResponse},
		"negative":    {http.StatusOK, `{"parameters":[],"total":-1}`, ErrInvalidResponse},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			client := newTestClient(t, server, server.URL, "gv.token", time.Second)
			client.namespace = "team-a"
			if _, err := client.ListParameters(context.Background(), ""); !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

// pagedParameterServer serves total synthetic parameters in pages, letting a
// test override the response of one request index.
func pagedParameterServer(t *testing.T, total int, override func(request, offset int) (string, bool)) (*httptest.Server, *[]int) {
	t.Helper()
	var offsets []int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		offset, err := strconv.Atoi(r.URL.Query().Get("offset"))
		if err != nil {
			t.Errorf("bad offset in %s", r.URL.String())
		}
		request := len(offsets)
		offsets = append(offsets, offset)
		if body, ok := override(request, offset); ok {
			_, _ = w.Write([]byte(body))
			return
		}
		end := offset + 200
		if end > total {
			end = total
		}
		_, _ = w.Write([]byte(parameterPageBody(offset, end, total)))
	}))
	t.Cleanup(server.Close)
	return server, &offsets
}

func parameterPageBody(from, to, total int) string {
	rows := make([]string, 0, to-from)
	for i := from; i < to; i++ {
		rows = append(rows, fmt.Sprintf(`{"name":"app/p%04d","value":"v","version":1}`, i))
	}
	return fmt.Sprintf(`{"parameters":[%s],"total":%d}`, strings.Join(rows, ","), total)
}

func listWith(t *testing.T, server *httptest.Server) ([]Parameter, error) {
	t.Helper()
	client := newTestClient(t, server, server.URL, "gv.secret-token", time.Second)
	client.namespace = "team-a"
	return client.ListParameters(context.Background(), "")
}

func TestListParametersReadsEveryPageInOrder(t *testing.T) {
	t.Parallel()
	server, offsets := pagedParameterServer(t, 450, func(int, int) (string, bool) { return "", false })
	parameters, err := listWith(t, server)
	if err != nil || len(parameters) != 450 {
		t.Fatalf("len = %d, error = %v", len(parameters), err)
	}
	for i, parameter := range parameters {
		if want := fmt.Sprintf("app/p%04d", i); parameter.Name != want {
			t.Fatalf("parameters[%d] = %s, want %s", i, parameter.Name, want)
		}
	}
	if fmt.Sprint(*offsets) != "[0 200 400]" {
		t.Fatalf("offsets = %v", *offsets)
	}
}

func TestListParametersSinglePageMakesOneRequest(t *testing.T) {
	t.Parallel()
	for _, total := range []int{0, 7, 200} {
		server, offsets := pagedParameterServer(t, total, func(int, int) (string, bool) { return "", false })
		parameters, err := listWith(t, server)
		if err != nil || len(parameters) != total || len(*offsets) != 1 {
			t.Fatalf("total %d: len = %d, requests = %v, error = %v", total, len(parameters), *offsets, err)
		}
	}
}

func TestListParametersRejectsInconsistentPaging(t *testing.T) {
	t.Parallel()
	const canary = "paging-body-canary"
	tests := map[string]struct {
		total    int
		override func(request, offset int) (string, bool)
	}{
		"empty page before total": {450, func(request, _ int) (string, bool) {
			return `{"parameters":[],"total":450}`, request == 1
		}},
		"total shrinks": {450, func(request, _ int) (string, bool) {
			return parameterPageBody(200, 400, 300), request == 1
		}},
		"total grows": {450, func(request, _ int) (string, bool) {
			return parameterPageBody(200, 400, 900), request == 1
		}},
		"offset does not advance": {450, func(request, _ int) (string, bool) {
			return parameterPageBody(0, 200, 450), request == 1
		}},
		"more rows than total": {450, func(request, _ int) (string, bool) {
			return parameterPageBody(200, 460, 450), request == 1
		}},
		"endless one-row pages": {100000, func(_, offset int) (string, bool) {
			return parameterPageBody(offset, offset+1, 100000), true
		}},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			server, offsets := pagedParameterServer(t, test.total, test.override)
			_, err := listWith(t, server)
			if !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("error = %v, want %v", err, ErrInvalidResponse)
			}
			assertRedacted(t, err, canary)
			assertRedacted(t, err, "gv.secret-token")
			assertRedacted(t, err, "app/p")
			if len(*offsets) > maxParameterPages {
				t.Fatalf("%d requests exceed the page bound", len(*offsets))
			}
		})
	}
}

func TestListParametersAcceptsPageLargerThanLimitWithinTotal(t *testing.T) {
	t.Parallel()
	// The client trusts the offset it asked for, not the page size: a server
	// that returns more rows than limit is accepted while rows stay within total.
	server, offsets := pagedParameterServer(t, 250, func(int, int) (string, bool) {
		return parameterPageBody(0, 250, 250), true
	})
	parameters, err := listWith(t, server)
	if err != nil || len(parameters) != 250 || len(*offsets) != 1 {
		t.Fatalf("len = %d, requests = %v, error = %v", len(parameters), *offsets, err)
	}
}
