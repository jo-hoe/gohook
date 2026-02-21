package hook

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

type recordedRequest struct {
	Method string
	URL    *url.URL
	Header http.Header
	Body   string
}

type recorderServer struct {
	srv      *httptest.Server
	mu       sync.Mutex
	requests []recordedRequest

	// response sequencing
	statuses []int
	delay    time.Duration
}

func newRecorderServer(statuses []int, delay time.Duration) *recorderServer {
	rs := &recorderServer{statuses: statuses, delay: delay}
	i := 0
	rs.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rs.delay > 0 {
			time.Sleep(rs.delay)
		}
		body := ""
		if r.Body != nil {
			b, _ := ioReadAll(r.Body)
			body = string(b)
		}
		_ = r.Body.Close()
		rs.mu.Lock()
		rs.requests = append(rs.requests, recordedRequest{
			Method: r.Method,
			URL:    r.URL,
			Header: r.Header.Clone(),
			Body:   body,
		})
		rs.mu.Unlock()
		code := 200
		if i < len(rs.statuses) {
			code = rs.statuses[i]
		}
		i++
		w.WriteHeader(code)
		_, _ = w.Write([]byte("ok"))
	}))
	return rs
}

func (rs *recorderServer) Close() {
	rs.srv.Close()
}

func (rs *recorderServer) URL() string {
	return rs.srv.URL
}

func (rs *recorderServer) Requests() []recordedRequest {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	out := make([]recordedRequest, len(rs.requests))
	copy(out, rs.requests)
	return out
}

// small wrapper to avoid introducing external deps in tests
func ioReadAll(r ioReader) ([]byte, error) {
	var b strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			_, _ = b.Write(buf[:n])
		}
		if err != nil {
			if errors.Is(err, ioEOF) {
				break
			}
			return []byte(b.String()), err
		}
	}
	return []byte(b.String()), nil
}

// minimal interfaces to avoid importing io explicitly at top
type ioReader interface {
	Read([]byte) (int, error)
}

var ioEOF = ioEOFType{}

type ioEOFType struct{}

func (ioEOFType) Error() string { return "EOF" }

func (ioEOFType) Unwrap() error { return nil }

// Test New validation
func TestNewValidationURLRequired(t *testing.T) {
	_, err := New(Config{})
	if err == nil || !strings.Contains(err.Error(), "URL is required") {
		t.Fatalf("expected URL required error, got %v", err)
	}
}

// Test default method selection
func TestDefaultMethodSelection(t *testing.T) {
	// Body empty => GET
	rs := newRecorderServer([]int{200}, 0)
	defer rs.Close()
	cfg := Config{
		URL: rs.URL(),
		// Method empty, Body empty
	}
	h, err := New(cfg)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	_, _, err = h.Execute(context.Background(), nil)
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}
	reqs := rs.Requests()
	if len(reqs) != 1 || reqs[0].Method != http.MethodGet {
		t.Fatalf("expected GET method, got %+v", reqs)
	}

	// Body non-empty => POST
	rs2 := newRecorderServer([]int{200}, 0)
	defer rs2.Close()
	cfg2 := Config{
		URL:  rs2.URL(),
		Body: "payload",
	}
	h2, err := New(cfg2)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	_, _, err = h2.Execute(context.Background(), nil)
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}
	reqs2 := rs2.Requests()
	if len(reqs2) != 1 || reqs2[0].Method != http.MethodPost {
		t.Fatalf("expected POST method, got %+v", reqs2)
	}
}

// Test templating of URL, headers, query, body, content type, helpers
func TestTemplatingAndHelpers(t *testing.T) {
	rs := newRecorderServer([]int{200}, 0)
	defer rs.Close()

	cfg := Config{
		URL:         rs.URL() + "/items?src={{ .Source }}&a=1&b=2",
		Method:      "",
		Headers:     map[string]string{"Authorization": "Bearer {{ .Token }}", "x-bar": "{{ .Bar | upper }}"},
		Query:       map[string]string{"b": "3", "c": "{{ .C }}", "q": "{{ .Query | urlencode }}"},
		ContentType: "application/{{ .Type }}",
		Body:        `{"name":"{{ .Name | trim | lower }}","tags":{{ json .Tags }}}`,
	}

	h, err := New(cfg)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}

	data := map[string]any{
		"Source": "gohook",
		"Token":  "abc123",
		"Bar":    "baz",
		"C":      "4",
		"Query":  "hello world",
		"Type":   "json",
		"Name":   "  Alice  ",
		"Tags":   []string{"a", "b"},
	}

	_, _, err = h.Execute(context.Background(), data)
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}

	reqs := rs.Requests()
	if len(reqs) != 1 {
		t.Fatalf("expected 1 request, got %d", len(reqs))
	}
	r := reqs[0]

	// Method should be POST due to non-empty body default
	if r.Method != http.MethodPost {
		t.Fatalf("expected POST, got %s", r.Method)
	}

	// Query merge: a=1, b=3 (overwritten), c=4, q=urlencoded
	q := r.URL.Query()
	if q.Get("a") != "1" || q.Get("b") != "3" || q.Get("c") != "4" || q.Get("q") != "hello+world" || q.Get("src") != "gohook" {
		t.Fatalf("unexpected query: %v", q)
	}

	// Headers: Authorization templated, x-bar canonicalized to X-Bar and upper applied, Content-Type templated
	if got := r.Header.Get("Authorization"); got != "Bearer abc123" {
		t.Fatalf("Authorization header mismatch: %q", got)
	}
	if got := r.Header.Get("X-Bar"); got != "BAZ" {
		t.Fatalf("X-Bar header mismatch: %q", got)
	}
	if got := r.Header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type header mismatch: %q", got)
	}

	// Body templated with trim/lower and json helper
	expectedBody := `{"name":"alice","tags":["a","b"]}`
	if r.Body != expectedBody {
		t.Fatalf("body mismatch:\nwant: %s\ngot:  %s", expectedBody, r.Body)
	}
}

// Content-Type should not override explicit header
func TestContentTypeDoesNotOverrideHeader(t *testing.T) {
	rs := newRecorderServer([]int{200}, 0)
	defer rs.Close()

	cfg := Config{
		URL:         rs.URL(),
		Headers:     map[string]string{"Content-Type": "text/plain"},
		ContentType: "application/{{ .Type }}",
		Body:        "x",
	}
	h, err := New(cfg)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	_, _, err = h.Execute(context.Background(), map[string]any{"Type": "json"})
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}
	reqs := rs.Requests()
	if len(reqs) != 1 {
		t.Fatalf("expected 1 request")
	}
	if ct := reqs[0].Header.Get("Content-Type"); ct != "text/plain" {
		t.Fatalf("expected Content-Type text/plain, got %q", ct)
	}
}

// Strict templates: error on missing key
func TestStrictTemplatesErrorOnMissing(t *testing.T) {
	cfg := Config{
		URL:             "http://example/{{ .Missing }}",
		StrictTemplates: true,
	}
	h, err := New(cfg)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	_, _, err = h.Execute(context.Background(), map[string]any{})
	if err == nil || !strings.Contains(err.Error(), "render URL") {
		t.Fatalf("expected render URL error for missing key, got %v", err)
	}
}

// Non-strict templates: render <no value>
func TestNonStrictTemplatesRendersNoValue(t *testing.T) {
	rs := newRecorderServer([]int{200}, 0)
	defer rs.Close()

	cfg := Config{
		URL:             rs.URL(),
		StrictTemplates: false,
		Headers:         map[string]string{"X-Missing": "{{ .Nope }}"},
	}
	h, err := New(cfg)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	_, _, err = h.Execute(context.Background(), map[string]any{})
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}
	reqs := rs.Requests()
	if len(reqs) != 1 {
		t.Fatalf("expected 1 request")
	}
	if v := reqs[0].Header.Get("X-Missing"); v != "<no value>" {
		t.Fatalf("expected <no value>, got %q", v)
	}
}

// ExpectedStatus and retries success path
func TestExpectedStatusRetriesSuccess(t *testing.T) {
	// Return 500 once, then 200
	rs := newRecorderServer([]int{500, 200}, 0)
	defer rs.Close()

	cfg := Config{
		URL:            rs.URL(),
		ExpectedStatus: []int{200},
		MaxRetries:     2,
		Backoff:        "10ms",
	}
	h, err := New(cfg)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	start := time.Now()
	_, _, err = h.Execute(context.Background(), nil)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Execute should succeed after retry, got %v", err)
	}
	reqs := rs.Requests()
	if len(reqs) != 2 {
		t.Fatalf("expected 2 attempts, got %d", len(reqs))
	}
	// backoff should have been applied at least ~10ms between attempts
	if elapsed < 10*time.Millisecond {
		t.Fatalf("expected elapsed >= backoff, got %v", elapsed)
	}
}

// ExpectedStatus retries exhaustion
func TestExpectedStatusRetriesExhaustion(t *testing.T) {
	// Always 500
	rs := newRecorderServer([]int{500, 500}, 0)
	defer rs.Close()

	cfg := Config{
		URL:            rs.URL(),
		ExpectedStatus: []int{200},
		MaxRetries:     1, // total attempts = 2
		Backoff:        "5ms",
	}
	h, err := New(cfg)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	_, _, err = h.Execute(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "unexpected status code") {
		t.Fatalf("expected unexpected status error, got %v", err)
	}
	reqs := rs.Requests()
	if len(reqs) != 2 {
		t.Fatalf("expected 2 attempts, got %d", len(reqs))
	}
}

// When ExpectedStatus is empty, any code is acceptable (no error)
func TestNoExpectedStatusAcceptsAnyCode(t *testing.T) {
	rs := newRecorderServer([]int{500}, 0)
	defer rs.Close()

	cfg := Config{
		URL: rs.URL(),
	}
	h, err := New(cfg)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	resp, body, err := h.Execute(context.Background(), nil)
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}
	if resp.StatusCode != 500 {
		t.Fatalf("expected status 500, got %d", resp.StatusCode)
	}
	if string(body) != "ok" {
		t.Fatalf("expected body ok, got %q", string(body))
	}
	// Verify response body is reset and readable again
	buf := make([]byte, 2)
	n, rerr := resp.Body.Read(buf)
	if rerr != nil && !errors.Is(rerr, ioEOF) {
		t.Fatalf("unexpected read error: %v", rerr)
	}
	if n == 0 {
		t.Fatalf("expected some bytes on second read")
	}
}

// Backoff parse validation
func TestBackoffParsing(t *testing.T) {
	// valid
	for _, s := range []string{"24s", "3m", "1h30m", "4d", "1w", "3m 4d"} {
		_, err := New(Config{URL: "http://example", Backoff: s})
		if err != nil {
			t.Fatalf("expected backoff %q to parse, got %v", s, err)
		}
	}
	// invalid
	_, err := New(Config{URL: "http://example", Backoff: "bogus"})
	if err == nil {
		t.Fatalf("expected error for invalid backoff")
	}
}

// Options: WithTimeout should override to cause timeout
func TestWithTimeoutCausesTimeout(t *testing.T) {
	rs := newRecorderServer([]int{200}, 50*time.Millisecond) // delay response
	defer rs.Close()

	cfg := Config{
		URL: rs.URL(),
	}
	h, err := New(cfg, WithTimeout(10*time.Millisecond))
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	_, _, err = h.Execute(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "Client.Timeout") {
		t.Fatalf("expected client timeout error, got %v", err)
	}
}

// Options: WithHTTPClient should ignore Config.InsecureSkipVerify
func TestWithHTTPClientIgnoresInsecureSkipVerify(t *testing.T) {
	// Self-signed TLS server
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer ts.Close()

	cfg := Config{
		URL:                ts.URL,
		InsecureSkipVerify: true, // would allow if default client used
	}
	custom := &http.Client{} // default transport, no InsecureSkipVerify
	h, err := New(cfg, WithHTTPClient(custom))
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	_, _, err = h.Execute(context.Background(), nil)
	if err == nil {
		t.Fatalf("expected x509 unknown authority error with custom client")
	}
	if !strings.Contains(err.Error(), "x509") {
		t.Fatalf("expected x509 error, got %v", err)
	}
}

// Options: WithInsecureSkipVerify best-effort on existing custom client with *http.Transport
func TestWithInsecureSkipVerifyBestEffortOnCustomClient(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer ts.Close()

	// Custom client with transport
	tr := &http.Transport{}
	custom := &http.Client{Transport: tr}

	cfg := Config{
		URL: ts.URL,
	}
	h, err := New(cfg, WithHTTPClient(custom), WithInsecureSkipVerify(true))
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	_, _, err = h.Execute(context.Background(), nil)
	if err != nil {
		t.Fatalf("expected success with best-effort InsecureSkipVerify, got %v", err)
	}
	// Verify that transport has InsecureSkipVerify true
	if rt, ok := h.client.Transport.(*http.Transport); ok {
		if rt.TLSClientConfig == nil || !rt.TLSClientConfig.InsecureSkipVerify {
			t.Fatalf("expected TLS InsecureSkipVerify to be true")
		}
	} else {
		t.Fatalf("expected *http.Transport")
	}
}

// Options: Config.InsecureSkipVerify applied on default client
func TestConfigInsecureSkipVerifyOnDefaultClient(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer ts.Close()

	// Without InsecureSkipVerify -> should fail
	h1, err := New(Config{URL: ts.URL})
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	_, _, err = h1.Execute(context.Background(), nil)
	if err == nil {
		t.Fatalf("expected x509 error without InsecureSkipVerify")
	}

	// With InsecureSkipVerify -> should succeed
	h2, err := New(Config{URL: ts.URL, InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	_, _, err = h2.Execute(context.Background(), nil)
	if err != nil {
		t.Fatalf("expected success with InsecureSkipVerify, got %v", err)
	}
}

// Test isExpectedStatus helper directly
func TestIsExpectedStatus(t *testing.T) {
	h := &Hook{cfg: Config{}}
	if !h.isExpectedStatus(500) {
		t.Fatalf("expected true when ExpectedStatus empty")
	}
	h2 := &Hook{cfg: Config{ExpectedStatus: []int{200, 201}}}
	if !h2.isExpectedStatus(201) || h2.isExpectedStatus(500) {
		t.Fatalf("isExpectedStatus logic incorrect")
	}
}

// Test parseK8sDuration directly
func TestParseK8sDuration(t *testing.T) {
	cases := []struct {
		in    string
		valid bool
	}{
		{"", true},
		{"10ms", true},
		{"1h30m", true},
		{"2d", true},
		{"1w", true},
		{"3m 4d", true},
		{"abc", false},
		{"10", false},
		{"5x", false},
	}
	for _, c := range cases {
		_, err := parseK8sDuration(c.in)
		if c.valid && err != nil {
			t.Fatalf("expected %q valid, got %v", c.in, err)
		}
		if !c.valid && err == nil {
			t.Fatalf("expected %q invalid", c.in)
		}
	}
}

// Verify that Execute returns the response body and leaves it readable again
func TestExecuteReturnsReadableBody(t *testing.T) {
	rs := newRecorderServer([]int{200}, 0)
	defer rs.Close()
	h, err := New(Config{URL: rs.URL()})
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	resp, body, err := h.Execute(context.Background(), nil)
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}
	if string(body) != "ok" {
		t.Fatalf("expected body 'ok', got %q", string(body))
	}
	// Verify we can read again
	all, _ := ioReadAll(resp.Body.(ioReader))
	if string(all) != "ok" {
		t.Fatalf("expected second read body 'ok', got %q", string(all))
	}
}

// Verify that WithStrictTemplates option overrides Config.StrictTemplates
func TestWithStrictTemplatesOptionOverrides(t *testing.T) {
	// Config false, option true -> should error on missing
	cfg := Config{
		URL:             "http://example/{{ .Missing }}",
		StrictTemplates: false,
	}
	h, err := New(cfg, WithStrictTemplates(true))
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	_, _, err = h.Execute(context.Background(), map[string]any{})
	if err == nil {
		t.Fatalf("expected error due to missing key with option override")
	}
}

// Verify WithHTTPClient respects Timeout via WithTimeout when client provided
func TestWithHTTPClientAndWithTimeout(t *testing.T) {
	rs := newRecorderServer([]int{200}, 50*time.Millisecond)
	defer rs.Close()

	custom := &http.Client{}
	h, err := New(Config{URL: rs.URL()}, WithHTTPClient(custom), WithTimeout(10*time.Millisecond))
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	_, _, err = h.Execute(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "Client.Timeout") {
		t.Fatalf("expected client timeout error, got %v", err)
	}
}

// Verify WithInsecureSkipVerify builds a default client if none provided
func TestWithInsecureSkipVerifyBuildsDefaultClient(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer ts.Close()

	h, err := New(Config{URL: ts.URL}, WithInsecureSkipVerify(true))
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	_, _, err = h.Execute(context.Background(), nil)
	if err != nil {
		t.Fatalf("expected success with WithInsecureSkipVerify(true), got %v", err)
	}
	// Ensure the client's transport is set accordingly
	if rt, ok := h.client.Transport.(*http.Transport); ok {
		if rt.TLSClientConfig == nil || !rt.TLSClientConfig.InsecureSkipVerify {
			t.Fatalf("expected TLS InsecureSkipVerify to be true on built client")
		}
	} else {
		t.Fatalf("expected *http.Transport")
	}
}

// Ensure canonicalization of header keys for templated keys too
func TestHeaderKeyTemplatingCanonicalization(t *testing.T) {
	rs := newRecorderServer([]int{200}, 0)
	defer rs.Close()

	cfg := Config{
		URL:     rs.URL(),
		Headers: map[string]string{"x-{{ .Key }}": "val"},
	}
	h, err := New(cfg)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	_, _, err = h.Execute(context.Background(), map[string]any{"Key": "test"})
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}
	reqs := rs.Requests()
	if len(reqs) != 1 {
		t.Fatalf("expected 1 request")
	}
	// Expect "X-Test"
	if got := reqs[0].Header.Get("X-Test"); got != "val" {
		t.Fatalf("expected header X-Test=val, got %q", got)
	}
}

// Ensure that when Content-Type is empty and not provided, no header is set
func TestNoContentTypeWhenNotProvided(t *testing.T) {
	rs := newRecorderServer([]int{200}, 0)
	defer rs.Close()
	h, err := New(Config{URL: rs.URL(), Body: "x"})
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	_, _, err = h.Execute(context.Background(), nil)
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}
	if ct := rs.Requests()[0].Header.Get("Content-Type"); ct != "" {
		t.Fatalf("expected no Content-Type header, got %q", ct)
	}
}

// Test TLS with Config.InsecureSkipVerify and custom RootCAs scenario
func TestTLSWithCustomTransportAndInsecure(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer ts.Close()

	// provide custom client without RootCAs but let WithInsecureSkipVerify try to patch it
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{},
	}
	custom := &http.Client{Transport: tr}
	h, err := New(Config{URL: ts.URL}, WithHTTPClient(custom), WithInsecureSkipVerify(true))
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	_, _, err = h.Execute(context.Background(), nil)
	if err != nil {
		t.Fatalf("expected success after best-effort insecure patch, got %v", err)
	}
}
