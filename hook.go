// Package goback provides a small dependency-free library to execute configurable,
// template-driven HTTP callbacks.
//
// # Overview
//
// - Configure an outbound HTTP request via Config (URL, method, headers, query, body).
// - Use Go text/template placeholders (e.g. {{ .Var }}) in any string field.
// - Call Execute(ctx, data) with a data object to render templates and send the request.
// - Configurable retries via ExpectedStatus (acceptable codes), MaxRetries (attempts), and Backoff (k8s-style duration, e.g., "30s", "3m", "4d").
// - No external dependencies; standard library only.
//
// Example:
//
//	cfg := goback.Config{
//	    URL:             \"https://api.example.com/items?src={{ .Source }}\",
//	    Method:          \"POST\",
//	    Headers:         map[string]string{\"Authorization\": \"Bearer {{ .Token }}\"},
//	    Query:           map[string]string{\"q\": \"{{ .Query }}\"},
//	    ContentType:     \"application/json\",
//	    Body:            `{\"id\":\"{{ .ID }}\",\"message\":\"{{ .Message | urlencode }}\"}`,
//	    Timeout:         \"10s\",
//	    StrictTemplates: true,
//	    ExpectedStatus:  []int{200, 201},
//	    MaxRetries:      3,
//	    Backoff:         \"30s\",
//	}
//	cb, err := goback.New(cfg)
//	if err != nil {
//	    panic(err)
//	}
//	resp, respBody, err := cb.Execute(context.Background(), map[string]any{
//	    \"Source\":  \"goback\",
//	    \"Token\":   \"abc123\",
//	    \"Query\":   \"search term\",
//	    \"ID\":      \"42\",
//	    \"Message\": \"hello world\",
//	})
//	_ = resp
//	_ = respBody
//	_ = err
package goback

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
	"text/template"
	"time"
)

// Config defines a single callback execution plan.
// All string fields support Go text/template placeholders ({{ ... }}),
// which are resolved at Execute time against the provided data object.
type Config struct {
	// URL is the target endpoint. May include template placeholders.
	URL string `yaml:"url"`

	// Method is the HTTP method (GET, POST, PUT, PATCH, DELETE, ...).
	// If empty, defaults to:
	// - POST when Body is non-empty
	// - GET otherwise
	Method string `yaml:"method"`

	// Headers are request headers. Values may contain templates.
	// Keys are treated as-is, but may also contain templates.
	Headers map[string]string `yaml:"headers"`

	// Query are query parameters to be added to the URL. Both keys and values
	// may contain templates. These are merged with the URL's existing query.
	Query map[string]string `yaml:"query"`

	// Body is the request body as a string (after templating). Optional.
	Body string `yaml:"body"`

	// Multipart defines a multipart/form-data body with in-memory file data.
	// When set, Body is ignored and Content-Type is set automatically with boundary.
	// Field names, field values, file field names, filenames, and per-file content types
	// may contain templates.
	Multipart *Multipart `yaml:"multipart"`

	// ContentType, if set and the "Content-Type" header is not already provided
	// by Headers, will be applied to the request.
	// May contain templates.
	ContentType string `yaml:"contentType"`

	// Timeout applies to the HTTP client used by this Callback, unless a custom
	// client is supplied via options. K8s-style duration string (e.g., "30s", "3m", "1h", "4d").
	// Empty means no explicit timeout (uses http.Client default).
	Timeout string `yaml:"timeout"`

	// InsecureSkipVerify disables TLS certificate verification when true.
	// Only applies to the default http.Client created by New.
	InsecureSkipVerify bool `yaml:"insecureSkipVerify"`

	// StrictTemplates controls missing key behavior:
	// - true: missing template variables cause an error (missingkey=error)
	// - false: missing variables render as <no value> (missingkey=default)
	StrictTemplates bool `yaml:"strictTemplates"`

	// ExpectedStatus lists acceptable HTTP response status codes.
	// When non-empty, any response code not in this list is considered unexpected
	// and will trigger retries (up to MaxRetries). When empty, status codes do not
	// affect success and are left to the caller to interpret.
	ExpectedStatus []int `yaml:"expectedStatus"`

	// MaxRetries controls how many retry attempts to make on transport errors
	// or unexpected status codes. 0 means no retries (single attempt).
	MaxRetries int `yaml:"maxRetries"`

	// Backoff is the delay between retries, parsed in a Kubernetes-style duration.
	// Examples: "24s", "3m", "1h30m", "4d", "1w", or a combination like "3m 4d".
	// When empty, no delay between attempts. Invalid values cause New to return an error.
	Backoff string `yaml:"backoff"`
}

// ByteFile represents an in-memory file part for multipart/form-data requests.
type ByteFile struct {
	// Field is the form field name for this file part (templated).
	Field string `yaml:"field"`
	// FileName is the filename to present to the server (templated; optional, defaults to "file").
	FileName string `yaml:"fileName"`
	// ContentType is an optional per-file content type (templated). If empty, defaults per mime/multipart to application/octet-stream.
	ContentType string `yaml:"contentType"`
	// Data holds the raw file content in memory.
	Data []byte `yaml:"-"`
}

// Multipart carries form fields and in-memory files to send.
// Field names, values, filenames, and content types support templates.
type Multipart struct {
	Fields map[string]string `yaml:"fields"`
	Files  []ByteFile        `yaml:"files"`
}

// Callback is a reusable executor for a callback Config.
//
// Callback is safe for concurrent use if the provided http.Client is safe for concurrent use
// (the default http.Client is).
type Callback struct {
	cfg        Config
	client     *http.Client
	strictTmpl bool
	backoff    time.Duration
}

// Option configures a Callback.
type Option func(*Callback)

// WithHTTPClient provides a custom http.Client. When provided, Timeout
// and InsecureSkipVerify from Config are not applied (the client is used as-is).
func WithHTTPClient(c *http.Client) Option {
	return func(h *Callback) {
		if c != nil {
			h.client = c
		}
	}
}

/* WithTimeout overrides Config.Timeout using a time.Duration. */
func WithTimeout(d time.Duration) Option {
	return func(h *Callback) {
		if h.client != nil {
			// respect existing client, just set its Timeout
			h.client.Timeout = d
			return
		}
		h.client = &http.Client{Timeout: d}
	}
}

// WithStrictTemplates overrides Config.StrictTemplates.
func WithStrictTemplates(strict bool) Option {
	return func(h *Callback) {
		h.strictTmpl = strict
	}
}

// WithInsecureSkipVerify enables/disables TLS verification on the default client.
// Ignored if a custom client is provided via WithHTTPClient.
func WithInsecureSkipVerify(insecure bool) Option {
	return func(h *Callback) {
		// only effective when building default client
		if h.client == nil {
			tr := cloneDefaultTransport()
			if tr.TLSClientConfig == nil {
				tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: insecure} // #nosec G402 - user opted in
			} else {
				tr.TLSClientConfig.InsecureSkipVerify = insecure // #nosec G402
			}
			h.client = &http.Client{Transport: tr}
		} else {
			// best-effort: try to update transport if it's an *http.Transport
			if rt, ok := h.client.Transport.(*http.Transport); ok && rt != nil {
				cp := rt.Clone()
				if cp.TLSClientConfig == nil {
					cp.TLSClientConfig = &tls.Config{InsecureSkipVerify: insecure} // #nosec G402
				} else {
					cp.TLSClientConfig.InsecureSkipVerify = insecure // #nosec G402
				}
				h.client.Transport = cp
			}
		}
	}
}

// New constructs a Callback from cfg and optional functional options.
// Validates minimal fields and prepares an http.Client when needed.
func New(cfg Config, opts ...Option) (*Callback, error) {
	if strings.TrimSpace(cfg.URL) == "" {
		return nil, errors.New("callback: URL is required")
	}

	// Choose default method if unset
	method := strings.TrimSpace(cfg.Method)
	if method == "" {
		if strings.TrimSpace(cfg.Body) != "" || cfg.Multipart != nil {
			method = http.MethodPost
		} else {
			method = http.MethodGet
		}
	}
	cfg.Method = method

	h := &Callback{
		cfg:        cfg,
		strictTmpl: cfg.StrictTemplates,
	}

	// Apply options first so user overrides take precedence.
	for _, opt := range opts {
		opt(h)
	}

	// Parse backoff
	if s := strings.TrimSpace(cfg.Backoff); s != "" {
		d, err := parseK8sDuration(s)
		if err != nil {
			return nil, wrapErr("parse backoff", err)
		}
		h.backoff = d
	}

	// If no custom client provided, build a default one honoring cfg flags.
	if h.client == nil {
		timeout := time.Duration(0)
		if s := strings.TrimSpace(cfg.Timeout); s != "" {
			d, err := parseK8sDuration(s)
			if err != nil {
				return nil, wrapErr("parse timeout", err)
			}
			timeout = d
		}
		tr := cloneDefaultTransport()
		if cfg.InsecureSkipVerify {
			if tr.TLSClientConfig == nil {
				tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402
			} else {
				tr.TLSClientConfig.InsecureSkipVerify = true // #nosec G402
			}
		}
		h.client = &http.Client{
			Timeout:   timeout,
			Transport: tr,
		}
	}

	return h, nil
}

// Execute renders the Callback's config with data and performs the HTTP request.
// Returns the http.Response (with Body reset to a fresh reader of the returned bytes),
// the response body bytes, and an error if any step fails.
//
// Non-2xx responses are not treated as errors by default unless ExpectedStatus is set.
// When ExpectedStatus is provided, any status not in the list triggers retries up to MaxRetries
// with Backoff delay between attempts; after exhausting retries, an error is returned.
func (h *Callback) Execute(ctx context.Context, data any) (*http.Response, []byte, error) {
	// Prepare static parts once
	method, err := h.renderMethod(data)
	if err != nil {
		return nil, nil, err
	}

	u, err := h.renderURLWithQuery(data)
	if err != nil {
		return nil, nil, err
	}

	headers, err := h.buildHeaders(data)
	if err != nil {
		return nil, nil, err
	}

	// If multipart is configured, build multipart body and use a per-attempt reader factory.
	if h.cfg.Multipart != nil {
		bodyBytes, contentType, err := h.buildMultipartBody(data, h.cfg.Multipart)
		if err != nil {
			return nil, nil, err
		}
		// Always set the multipart Content-Type with boundary for this request.
		headers.Set("Content-Type", contentType)

		bodyFactory := func() io.Reader {
			if len(bodyBytes) == 0 {
				return nil
			}
			return bytes.NewReader(bodyBytes)
		}
		return h.executeWithBodyFactory(ctx, method, u.String(), headers, bodyFactory)
	}

	// Otherwise, render string body and use a per-attempt reader factory.
	renderedBody, err := h.renderBodyString(data)
	if err != nil {
		return nil, nil, err
	}
	bodyFactory := func() io.Reader {
		if strings.TrimSpace(renderedBody) == "" {
			return nil
		}
		return strings.NewReader(renderedBody)
	}
	return h.executeWithBodyFactory(ctx, method, u.String(), headers, bodyFactory)
}

// renderMethod renders and validates the HTTP method.
func (h *Callback) renderMethod(data any) (string, error) {
	method, err := h.renderString(h.cfg.Method, data)
	if err != nil {
		return "", wrapErr("render method", err)
	}
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		return "", errors.New("callback: rendered method empty")
	}
	return method, nil
}

// renderURLWithQuery renders the URL and merges any configured query parameters.
func (h *Callback) renderURLWithQuery(data any) (*url.URL, error) {
	rawURL, err := h.renderString(h.cfg.URL, data)
	if err != nil {
		return nil, wrapErr("render URL", err)
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, wrapErr("parse URL", err)
	}

	q := u.Query()
	if len(h.cfg.Query) > 0 {
		renderedQ, err := h.renderStringMap(h.cfg.Query, data)
		if err != nil {
			return nil, wrapErr("render query", err)
		}
		for k, v := range renderedQ {
			q.Set(k, v)
		}
	}
	u.RawQuery = q.Encode()
	return u, nil
}

// buildHeaders renders configured headers and content type.
func (h *Callback) buildHeaders(data any) (http.Header, error) {
	headers := make(http.Header)
	if len(h.cfg.Headers) > 0 {
		renderedH, err := h.renderStringMap(h.cfg.Headers, data)
		if err != nil {
			return nil, wrapErr("render headers", err)
		}
		for k, v := range renderedH {
			hk := http.CanonicalHeaderKey(strings.TrimSpace(k))
			if hk != "" {
				headers.Set(hk, v)
			}
		}
	}

	if ct := strings.TrimSpace(h.cfg.ContentType); ct != "" && headers.Get("Content-Type") == "" {
		rct, err := h.renderString(ct, data)
		if err != nil {
			return nil, wrapErr("render content-type", err)
		}
		if strings.TrimSpace(rct) != "" {
			headers.Set("Content-Type", rct)
		}
	}
	return headers, nil
}

// renderBodyString renders the request body once for reuse across attempts.
func (h *Callback) renderBodyString(data any) (string, error) {
	if strings.TrimSpace(h.cfg.Body) == "" {
		return "", nil
	}
	rb, err := h.renderString(h.cfg.Body, data)
	if err != nil {
		return "", wrapErr("render body", err)
	}
	return rb, nil
}

// readAndResetBody reads the response body and resets it so the caller can read again.
func (h *Callback) readAndResetBody(resp *http.Response) ([]byte, error) {
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		_ = resp.Body.Close()
		return nil, wrapErr("read response body", err)
	}
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(respBody))
	return respBody, nil
}

// waitBackoff waits for the configured backoff duration or context cancellation.
func (h *Callback) waitBackoff(ctx context.Context) error {
	if h.backoff <= 0 {
		return nil
	}
	t := time.NewTimer(h.backoff)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return wrapErr("retry wait canceled", ctx.Err())
	}
}

// executeWithBodyFactory performs attempts with retries using a body factory to create a fresh reader per attempt.
func (h *Callback) executeWithBodyFactory(ctx context.Context, method, urlStr string, headers http.Header, bodyFactory func() io.Reader) (*http.Response, []byte, error) {
	var lastResp *http.Response
	var lastBody []byte
	var lastErr error

	for attempt := 0; attempt <= h.cfg.MaxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, urlStr, bodyFactory())
		if err != nil {
			// Building a request failed; treat as fatal for this call.
			return nil, nil, wrapErr("build request", err)
		}
		req.Header = headers

		resp, err := h.client.Do(req)
		if err != nil {
			lastResp, lastBody, lastErr = nil, nil, wrapErr("do request", err)
		} else {
			respBody, rerr := h.readAndResetBody(resp)
			if rerr != nil {
				lastResp, lastBody, lastErr = resp, nil, rerr
			} else if h.isExpectedStatus(resp.StatusCode) {
				return resp, respBody, nil
			} else {
				lastResp, lastBody, lastErr = resp, respBody, fmt.Errorf("callback: unexpected status code %d", resp.StatusCode)
			}
		}

		if attempt < h.cfg.MaxRetries {
			if werr := h.waitBackoff(ctx); werr != nil {
				return lastResp, lastBody, werr
			}
		}
	}

	return lastResp, lastBody, lastErr
}

// renderString renders a single template string with the provided data.
// If strict templates are enabled and a missing key is encountered, an error is returned.
// If the string does not contain "{{", it is returned as-is for performance.
func (h *Callback) renderString(s string, data any) (string, error) {
	if s == "" {
		return "", nil
	}
	// Simple fast-path: likely no template markers
	if !strings.Contains(s, "{{") {
		return s, nil
	}

	tpl := template.New("tpl").Funcs(h.funcs())
	if h.strictTmpl {
		tpl = tpl.Option("missingkey=error")
	} else {
		tpl = tpl.Option("missingkey=default")
	}
	parsed, err := tpl.Parse(s)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := parsed.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// renderStringMap renders both keys and values of a map[string]string with templates.
func (h *Callback) renderStringMap(m map[string]string, data any) (map[string]string, error) {
	if len(m) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		rk, err := h.renderString(k, data)
		if err != nil {
			return nil, err
		}
		rv, err := h.renderString(v, data)
		if err != nil {
			return nil, err
		}
		out[rk] = rv
	}
	return out, nil
}

// funcs returns helper functions available inside templates.
// These are intentionally small and dependency-free.
func (h *Callback) funcs() template.FuncMap {
	return template.FuncMap{
		// json encodes a value to a JSON string.
		"json": func(v any) (string, error) {
			b, err := json.Marshal(v)
			if err != nil {
				return "", err
			}
			return string(b), nil
		},
		// urlencode applies URL query escaping.
		"urlencode": url.QueryEscape,
		// lower/upper/trim for simple string massaging.
		"lower": strings.ToLower,
		"upper": strings.ToUpper,
		"trim":  strings.TrimSpace,
		// join joins a string slice with a separator.
		"join": func(elems []string, sep string) string { return strings.Join(elems, sep) },
	}
}

// isExpectedStatus returns true if the given HTTP status code is acceptable
// under this Callback's configuration.
func (h *Callback) isExpectedStatus(code int) bool {
	if len(h.cfg.ExpectedStatus) == 0 {
		return true
	}
	for _, s := range h.cfg.ExpectedStatus {
		if code == s {
			return true
		}
	}
	return false
}

// buildMultipartBody builds and renders a multipart/form-data request using in-memory file data.
// It renders templated entries and assembles the multipart body in memory.
func (h *Callback) buildMultipartBody(data any, mp *Multipart) ([]byte, string, error) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)

	// Fields
	if len(mp.Fields) > 0 {
		rendered, err := h.renderStringMap(mp.Fields, data)
		if err != nil {
			_ = w.Close()
			return nil, "", wrapErr("render multipart fields", err)
		}
		for k, v := range rendered {
			if err := w.WriteField(strings.TrimSpace(k), v); err != nil {
				_ = w.Close()
				return nil, "", wrapErr("write multipart field", err)
			}
		}
	}

	// Files
	for i := range mp.Files {
		f := mp.Files[i]

		field, err := h.renderString(f.Field, data)
		if err != nil {
			_ = w.Close()
			return nil, "", wrapErr("render file field", err)
		}
		field = strings.TrimSpace(field)
		if field == "" {
			_ = w.Close()
			return nil, "", errors.New("callback: multipart file field empty after rendering")
		}

		filename := strings.TrimSpace(f.FileName)
		if filename == "" {
			filename = "file"
		}
		filename, err = h.renderString(filename, data)
		if err != nil {
			_ = w.Close()
			return nil, "", wrapErr("render file filename", err)
		}

		ct := strings.TrimSpace(f.ContentType)
		if ct != "" {
			ct, err = h.renderString(ct, data)
			if err != nil {
				_ = w.Close()
				return nil, "", wrapErr("render file content-type", err)
			}
			hdr := make(textproto.MIMEHeader)
			hdr.Set("Content-Disposition", fmt.Sprintf(`form-data; name="%s"; filename="%s"`, field, filename))
			hdr.Set("Content-Type", ct)
			part, err := w.CreatePart(hdr)
			if err != nil {
				_ = w.Close()
				return nil, "", wrapErr("create multipart part", err)
			}
			if _, err := part.Write(f.Data); err != nil {
				_ = w.Close()
				return nil, "", wrapErr("write multipart bytes", err)
			}
		} else {
			part, err := w.CreateFormFile(field, filename)
			if err != nil {
				_ = w.Close()
				return nil, "", wrapErr("create multipart file", err)
			}
			if _, err := part.Write(f.Data); err != nil {
				_ = w.Close()
				return nil, "", wrapErr("write multipart bytes", err)
			}
		}
	}

	if err := w.Close(); err != nil {
		return nil, "", wrapErr("finalize multipart body", err)
	}
	return buf.Bytes(), w.FormDataContentType(), nil
}

// parseK8sDuration parses a duration string similar to Go's time.ParseDuration,
// extended with 'd' (days) and 'w' (weeks) units and allowing token concatenation
// and/or whitespace separation (e.g., "1h30m", "3m 4d"). Only non-negative
// integer values are supported (no decimals, no signs).
func parseK8sDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	// Try native parser first (handles concatenated tokens, no spaces, no days/weeks).
	if d, err := time.ParseDuration(s); err == nil {
		return d, nil
	}

	units := map[string]time.Duration{
		"ns": time.Nanosecond,
		"us": time.Microsecond,
		"ms": time.Millisecond,
		"s":  time.Second,
		"m":  time.Minute,
		"h":  time.Hour,
		"d":  24 * time.Hour,
		"w":  7 * 24 * time.Hour,
	}

	var total time.Duration
	for i := 0; i < len(s); i++ {
		i = skipSpaces(s, i)
		if i >= len(s) {
			break
		}
		start := i

		// read integer value
		val, next, ok := readInt64Token(s, i)
		if !ok {
			return 0, errors.New("invalid duration: expected number at: " + s[start:])
		}
		i = next

		// read unit letters
		unitStr, nextU, ok := readLettersToken(s, i)
		if !ok {
			return 0, errors.New("invalid duration: missing unit after number at: " + s[start:])
		}
		i = nextU

		mult, ok := units[strings.ToLower(unitStr)]
		if !ok {
			return 0, errors.New("invalid duration: unknown unit " + strings.ToLower(unitStr))
		}
		total += time.Duration(val) * mult
	}
	return total, nil
}

// Helpers for parseK8sDuration to reduce branching and improve readability.

func isSpace(b byte) bool {
	switch b {
	case ' ', '\t', '\n', '\r':
		return true
	default:
		return false
	}
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

func isLetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func skipSpaces(s string, i int) int {
	for i < len(s) && isSpace(s[i]) {
		i++
	}
	return i
}

func readInt64Token(s string, i int) (int64, int, bool) {
	if i >= len(s) || !isDigit(s[i]) {
		return 0, i, false
	}
	var v int64
	for i < len(s) && isDigit(s[i]) {
		v = v*10 + int64(s[i]-'0')
		i++
	}
	return v, i, true
}

func readLettersToken(s string, i int) (string, int, bool) {
	if i >= len(s) || !isLetter(s[i]) {
		return "", i, false
	}
	start := i
	for i < len(s) && isLetter(s[i]) {
		i++
	}
	return s[start:i], i, true
}

func wrapErr(stage string, err error) error {
	return errors.New("callback: " + stage + ": " + err.Error())
}

func cloneDefaultTransport() *http.Transport {
	// Start from http.DefaultTransport settings
	base, _ := http.DefaultTransport.(*http.Transport)
	if base == nil {
		return &http.Transport{}
	}
	return base.Clone()
}