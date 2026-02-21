package goback

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewHookExecutor_NilClient_UsesConfigFlags(t *testing.T) {
	t.Run("InsecureSkipVerify allows TLS server", func(t *testing.T) {
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			_, _ = w.Write([]byte("ok"))
		}))
		defer ts.Close()

		exec, err := NewCallbackExecutor(Config{
			URL:                ts.URL,
			InsecureSkipVerify: true,
		}, nil)
		if err != nil {
			t.Fatalf("NewHookExecutor error: %v", err)
		}
		_, _, err = exec.Execute(context.Background(), TemplateData{})
		if err != nil {
			t.Fatalf("Execute error with insecure TLS: %v", err)
		}
	})

	t.Run("Timeout enforced on default client", func(t *testing.T) {
		rs := newRecorderServer([]int{200}, 50*time.Millisecond)
		defer rs.Close()

		exec, err := NewCallbackExecutor(Config{
			URL:     rs.URL(),
			Timeout: "10ms",
		}, nil)
		if err != nil {
			t.Fatalf("NewHookExecutor error: %v", err)
		}
		_, _, err = exec.Execute(context.Background(), TemplateData{})
		if err == nil || !strings.Contains(err.Error(), "Client.Timeout") {
			t.Fatalf("expected client timeout error, got %v", err)
		}
	})
}

func TestNewHookExecutor_WithCustomClient_IgnoresConfigInsecureSkipVerify(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer ts.Close()

	custom := &http.Client{} // no InsecureSkipVerify
	exec, err := NewCallbackExecutor(Config{
		URL:                ts.URL,
		InsecureSkipVerify: true, // should be ignored because custom client is provided
	}, custom)
	if err != nil {
		t.Fatalf("NewHookExecutor error: %v", err)
	}
	_, _, err = exec.Execute(context.Background(), TemplateData{})
	if err == nil {
		t.Fatalf("expected x509 unknown authority error with custom client")
	}
	if !strings.Contains(err.Error(), "x509") {
		t.Fatalf("expected x509 error, got %v", err)
	}
}

func TestHookExecutor_Execute_MapsTemplateDataAndDelegates(t *testing.T) {
	rs := newRecorderServer([]int{200}, 0)
	defer rs.Close()

	cfg := Config{
		URL:         rs.URL() + "/echo/{{ .id }}?q={{ .query | urlencode }}",
		Headers:     map[string]string{"X-Name": "{{ .name }}"},
		ContentType: "text/plain",
		Body:        "{{ .message }}",
		// Method intentionally left empty to rely on default (POST because Body non-empty)
	}
	exec, err := NewCallbackExecutor(cfg, nil)
	if err != nil {
		t.Fatalf("NewHookExecutor error: %v", err)
	}

	data := TemplateData{Values: map[string]string{
		"id":      "42",
		"query":   "hello world",
		"name":    "alice",
		"message": "hi",
	}}
	_, _, err = exec.Execute(context.Background(), data)
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}

	reqs := rs.Requests()
	if len(reqs) != 1 {
		t.Fatalf("expected 1 request, got %d", len(reqs))
	}
	r := reqs[0]
	if r.Method != http.MethodPost {
		t.Fatalf("expected POST, got %s", r.Method)
	}
	if r.URL.Path != "/echo/42" {
		t.Fatalf("expected path /echo/42, got %s", r.URL.Path)
	}
	if q := r.URL.Query().Get("q"); q != "hello+world" && q != "hello world" {
		// Depending on server parsing, but httptest server will show '+' in raw query decode as 'hello world'
		if q != "hello world" {
			t.Fatalf("unexpected query q: %q", q)
		}
	}
	if got := r.Header.Get("X-Name"); got != "alice" {
		t.Fatalf("header X-Name mismatch: %q", got)
	}
	if got := r.Header.Get("Content-Type"); got != "text/plain" {
		t.Fatalf("Content-Type mismatch: %q", got)
	}
	if r.Body != "hi" {
		t.Fatalf("body mismatch: want %q, got %q", "hi", r.Body)
	}
}

func TestHookExecutor_Execute_StrictTemplatesMissingKeyErrors(t *testing.T) {
	exec, err := NewCallbackExecutor(Config{
		URL:             "http://example/{{ .missing }}",
		StrictTemplates: true,
	}, nil)
	if err != nil {
		t.Fatalf("NewHookExecutor error: %v", err)
	}
	_, _, err = exec.Execute(context.Background(), TemplateData{Values: map[string]string{}})
	if err == nil || !strings.Contains(err.Error(), "render URL") {
		t.Fatalf("expected render URL error due to missing key, got %v", err)
	}
}

// multipartRecorderServer records multipart/form-data requests for assertions.
type multipartRecorderServer struct {
	srv           *httptest.Server
	lastRequest   *http.Request
	lastFieldVals map[string]string
	lastFileName  string
	lastFileBytes []byte
}

func newMultipartRecorderServer(status int) *multipartRecorderServer {
	m := &multipartRecorderServer{}
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.lastRequest = r

		// Expect multipart
		ct := r.Header.Get("Content-Type")
		if !strings.HasPrefix(ct, "multipart/form-data; boundary=") {
			w.WriteHeader(400)
			_, _ = w.Write([]byte("expected multipart"))
			return
		}

		// Parse form
		if err := r.ParseMultipartForm(10 << 20); err != nil {
			w.WriteHeader(400)
			_, _ = w.Write([]byte("parse error: " + err.Error()))
			return
		}

		m.lastFieldVals = make(map[string]string)
		for k, vals := range r.MultipartForm.Value {
			if len(vals) > 0 {
				m.lastFieldVals[k] = vals[0]
			}
		}

		// Expect one file under field "file"
		if r.MultipartForm.File != nil {
			if files := r.MultipartForm.File["file"]; len(files) > 0 {
				fh := files[0]
				m.lastFileName = fh.Filename
				f, err := fh.Open()
				if err == nil {
					defer func() { _ = f.Close() }()
					m.lastFileBytes, _ = io.ReadAll(f)
				}
			}
		}

		w.WriteHeader(status)
		_, _ = w.Write([]byte("ok"))
	}))
	return m
}

func (m *multipartRecorderServer) Close()      { m.srv.Close() }
func (m *multipartRecorderServer) URL() string { return m.srv.URL }

func TestHook_ExecuteMultipart_InMemoryBytes(t *testing.T) {
	rs := newMultipartRecorderServer(201)
	defer rs.Close()

	cfg := Config{
		URL:            rs.URL() + "/upload?src={{ .Source }}",
		Headers:        map[string]string{"Authorization": "Bearer {{ .Token }}"},
		ExpectedStatus: []int{201},
		Multipart: &Multipart{
			Fields: map[string]string{
				"title": "{{ .Title }}",
				"note":  "{{ .Note }}",
			},
			Files: []ByteFile{
				{
					Field:       "file",
					FileName:    "report-{{ .Quarter }}.pdf",
					ContentType: "application/pdf",
					Data:        []byte("%PDF-FAKE%"),
				},
			},
		},
	}
	h, err := New(cfg)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}

	resp, body, err := h.Execute(context.Background(), map[string]any{
		"Source":  "goback",
		"Token":   "abc123",
		"Title":   "Report",
		"Note":    "Please review",
		"Quarter": "Q1",
	})
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}
	if resp.StatusCode != 201 {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}
	if string(body) != "ok" {
		t.Fatalf("expected body ok, got %q", string(body))
	}

	// Assertions on recorded request
	if rs.lastRequest == nil {
		t.Fatalf("no request recorded")
	}
	if rs.lastRequest.Method != http.MethodPost {
		t.Fatalf("expected POST, got %s", rs.lastRequest.Method)
	}
	if rs.lastRequest.URL.Query().Get("src") != "goback" {
		t.Fatalf("expected query src=goback")
	}
	if got := rs.lastRequest.Header.Get("Authorization"); got != "Bearer abc123" {
		t.Fatalf("auth header mismatch: %q", got)
	}

	// Fields
	if rs.lastFieldVals["title"] != "Report" {
		t.Fatalf("field title mismatch: %q", rs.lastFieldVals["title"])
	}
	if rs.lastFieldVals["note"] != "Please review" {
		t.Fatalf("field note mismatch: %q", rs.lastFieldVals["note"])
	}

	// File
	if rs.lastFileName != "report-Q1.pdf" {
		t.Fatalf("filename mismatch: %q", rs.lastFileName)
	}
	if string(rs.lastFileBytes) != "%PDF-FAKE%" {
		t.Fatalf("file content mismatch: %q", string(rs.lastFileBytes))
	}
}

func TestHookExecutor_ExecuteMultipart_Typed(t *testing.T) {
	rs := newMultipartRecorderServer(200)
	defer rs.Close()

	cfg := Config{
		URL:            rs.URL() + "/typed?src={{ .source }}",
		Headers:        map[string]string{"X-Req": "{{ .reqid }}"},
		ExpectedStatus: []int{200},
		Multipart: &Multipart{
			Fields: map[string]string{
				"a": "{{ .a }}",
				"b": "{{ .b }}",
			},
			Files: []ByteFile{
				{Field: "file", FileName: "x.txt", Data: []byte("hello")},
			},
		},
	}
	exec, err := NewCallbackExecutor(cfg, nil)
	if err != nil {
		t.Fatalf("NewHookExecutor error: %v", err)
	}

	resp, body, err := exec.Execute(context.Background(), TemplateData{
		Values: map[string]string{
			"source": "typed",
			"reqid":  "r123",
			"a":      "1",
			"b":      "2",
		},
	})
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if string(body) != "ok" {
		t.Fatalf("expected body ok, got %q", string(body))
	}

	// Assertions
	if rs.lastRequest == nil {
		t.Fatalf("no request recorded")
	}
	if rs.lastRequest.Method != http.MethodPost {
		t.Fatalf("expected POST, got %s", rs.lastRequest.Method)
	}
	if rs.lastRequest.URL.Query().Get("src") != "typed" {
		t.Fatalf("expected query src=typed")
	}
	if got := rs.lastRequest.Header.Get("X-Req"); got != "r123" {
		t.Fatalf("header X-Req mismatch: %q", got)
	}
	if rs.lastFieldVals["a"] != "1" || rs.lastFieldVals["b"] != "2" {
		t.Fatalf("field values mismatch: %+v", rs.lastFieldVals)
	}
	if rs.lastFileName != "x.txt" || string(rs.lastFileBytes) != "hello" {
		t.Fatalf("file mismatch: name=%q bytes=%q", rs.lastFileName, string(rs.lastFileBytes))
	}
}