package client

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
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
