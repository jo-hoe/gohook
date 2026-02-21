package hook

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"text/template"
	"time"
)

// Package hook provides a small dependency-free library to execute configurable,
// template-driven HTTP webhooks.
//
// Overview
//
// - Configure an outbound HTTP request via Config (URL, method, headers, query, body).
// - Use Go text/template placeholders (e.g. {{ .Var }}) in any string field.
// - Call Execute(ctx, data) with a data object to render templates and send the request.
// - Configurable retries via ExpectedStatus (acceptable codes), MaxRetries (attempts), and Backoff (k8s-style duration, e.g., "30s", "3m", "4d").
// - No external dependencies; standard library only.
//
// Example:
//
//	cfg := hook.Config{
//		URL:             "https://api.example.com/items?src={{ .Source }}",
//		Method:          "POST",
//		Headers:         map[string]string{"Authorization": "Bearer {{ .Token }}"},
//		Query:           map[string]string{"q": "{{ .Query }}"},
//		ContentType:     "application/json",
//		Body:            `{"id":"{{ .ID }}","message":"{{ .Message | urlencode }}"}`,
//		TimeoutSeconds:  10,
//		StrictTemplates: true,
//		ExpectedStatus:  []int{200, 201},
//		MaxRetries:      3,
//		Backoff:         "30s",
//	}
//	h, err := hook.New(cfg)
//	if err != nil {
//		panic(err)
//	}
//	resp, respBody, err := h.Execute(context.Background(), map[string]any{
//		"Source":  "gohook",
//		"Token":   "abc123",
//		"Query":   "search term",
//		"ID":      "42",
//		"Message": "hello world",
//	})
//	_ = resp
//	_ = respBody
//	_ = err

// Config defines a single webhook execution plan.
// All string fields support Go text/template placeholders ({{ ... }}),
// which are resolved at Execute time against the provided data object.
type Config struct {
	// URL is the target endpoint. May include template placeholders.
	URL string

	// Method is the HTTP method (GET, POST, PUT, PATCH, DELETE, ...).
	// If empty, defaults to:
	// - POST when Body is non-empty
	// - GET otherwise
	Method string

	// Headers are request headers. Values may contain templates.
	// Keys are treated as-is, but may also contain templates.
	Headers map[string]string

	// Query are query parameters to be added to the URL. Both keys and values
	// may contain templates. These are merged with the URL's existing query.
	Query map[string]string

	// Body is the request body as a string (after templating). Optional.
	Body string

	// ContentType, if set and the "Content-Type" header is not already provided
	// by Headers, will be applied to the request.
	// May contain templates.
	ContentType string

	// TimeoutSeconds applies to the HTTP client used by this Hook, unless a custom
	// client is supplied via options. 0 means no explicit timeout (uses http.Client default).
	TimeoutSeconds int

	// InsecureSkipVerify disables TLS certificate verification when true.
	// Only applies to the default http.Client created by New.
	InsecureSkipVerify bool

	// StrictTemplates controls missing key behavior:
	// - true: missing template variables cause an error (missingkey=error)
	// - false: missing variables render as <no value> (missingkey=default)
	StrictTemplates bool

	// ExpectedStatus lists acceptable HTTP response status codes.
	// When non-empty, any response code not in this list is considered unexpected
	// and will trigger retries (up to MaxRetries). When empty, status codes do not
	// affect success and are left to the caller to interpret.
	ExpectedStatus []int

	// MaxRetries controls how many retry attempts to make on transport errors
	// or unexpected status codes. 0 means no retries (single attempt).
	MaxRetries int

	// Backoff is the delay between retries, parsed in a Kubernetes-style duration.
	// Examples: "24s", "3m", "1h30m", "4d", "1w", or a combination like "3m 4d".
	// When empty, no delay between attempts. Invalid values cause New to return an error.
	Backoff string
}

// Hook is a reusable executor for a webhook Config.
//
// Hook is safe for concurrent use if the provided http.Client is safe for concurrent use
// (the default http.Client is).
type Hook struct {
	cfg        Config
	client     *http.Client
	strictTmpl bool
	backoff    time.Duration
}

// Option configures a Hook.
type Option func(*Hook)

// WithHTTPClient provides a custom http.Client. When provided, TimeoutSeconds
// and InsecureSkipVerify from Config are not applied (the client is used as-is).
func WithHTTPClient(c *http.Client) Option {
	return func(h *Hook) {
		if c != nil {
			h.client = c
		}
	}
}

// WithTimeout overrides Config.TimeoutSeconds using a time.Duration.
func WithTimeout(d time.Duration) Option {
	return func(h *Hook) {
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
	return func(h *Hook) {
		h.strictTmpl = strict
	}
}

// WithInsecureSkipVerify enables/disables TLS verification on the default client.
// Ignored if a custom client is provided via WithHTTPClient.
func WithInsecureSkipVerify(insecure bool) Option {
	return func(h *Hook) {
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

// New constructs a Hook from cfg and optional functional options.
// Validates minimal fields and prepares an http.Client when needed.
func New(cfg Config, opts ...Option) (*Hook, error) {
	if strings.TrimSpace(cfg.URL) == "" {
		return nil, errors.New("hook: URL is required")
	}

	// Choose default method if unset
	method := strings.TrimSpace(cfg.Method)
	if method == "" {
		if strings.TrimSpace(cfg.Body) != "" {
			method = http.MethodPost
		} else {
			method = http.MethodGet
		}
	}
	cfg.Method = method

	h := &Hook{
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
		if cfg.TimeoutSeconds > 0 {
			timeout = time.Duration(cfg.TimeoutSeconds) * time.Second
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

// Execute renders the Hook's config with data and performs the HTTP request.
// Returns the http.Response (with Body reset to a fresh reader of the returned bytes),
// the response body bytes, and an error if any step fails.
//
// Non-2xx responses are not treated as errors by default unless ExpectedStatus is set.
// When ExpectedStatus is provided, any status not in the list triggers retries up to MaxRetries
// with Backoff delay between attempts; after exhausting retries, an error is returned.
func (h *Hook) Execute(ctx context.Context, data any) (*http.Response, []byte, error) {
	// Render method
	method, err := h.renderString(h.cfg.Method, data)
	if err != nil {
		return nil, nil, wrapErr("render method", err)
	}
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		return nil, nil, errors.New("hook: rendered method empty")
	}

	// Render URL
	rawURL, err := h.renderString(h.cfg.URL, data)
	if err != nil {
		return nil, nil, wrapErr("render URL", err)
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, nil, wrapErr("parse URL", err)
	}

	// Merge query params: from URL + from cfg.Query (templated)
	q := u.Query()
	if len(h.cfg.Query) > 0 {
		renderedQ, err := h.renderStringMap(h.cfg.Query, data)
		if err != nil {
			return nil, nil, wrapErr("render query", err)
		}
		for k, v := range renderedQ {
			// Support comma-separated multi-values? Keep it simple: Set.
			q.Set(k, v)
		}
	}
	u.RawQuery = q.Encode()

	// Render headers
	headers := make(http.Header)
	if len(h.cfg.Headers) > 0 {
		renderedH, err := h.renderStringMap(h.cfg.Headers, data)
		if err != nil {
			return nil, nil, wrapErr("render headers", err)
		}
		for k, v := range renderedH {
			hk := http.CanonicalHeaderKey(strings.TrimSpace(k))
			if hk != "" {
				headers.Set(hk, v)
			}
		}
	}

	// Render content type (unless already set in headers)
	if ct := strings.TrimSpace(h.cfg.ContentType); ct != "" && headers.Get("Content-Type") == "" {
		rct, err := h.renderString(ct, data)
		if err != nil {
			return nil, nil, wrapErr("render content-type", err)
		}
		if strings.TrimSpace(rct) != "" {
			headers.Set("Content-Type", rct)
		}
	}

	// Render body once; reuse for each attempt
	var renderedBody string
	if strings.TrimSpace(h.cfg.Body) != "" {
		rb, err := h.renderString(h.cfg.Body, data)
		if err != nil {
			return nil, nil, wrapErr("render body", err)
		}
		renderedBody = rb
	}

	var lastResp *http.Response
	var lastBody []byte
	var lastErr error

	max := h.cfg.MaxRetries
	for attempt := 0; attempt <= max; attempt++ {
		// Build request per attempt (new body reader each time)
		var bodyReader io.Reader
		if strings.TrimSpace(renderedBody) != "" {
			bodyReader = strings.NewReader(renderedBody)
		}
		req, err := http.NewRequestWithContext(ctx, method, u.String(), bodyReader)
		if err != nil {
			return nil, nil, wrapErr("build request", err)
		}
		req.Header = headers

		// Perform request
		resp, err := h.client.Do(req)
		if err != nil {
			lastResp, lastBody, lastErr = nil, nil, wrapErr("do request", err)
		} else {
			// Read entire response body, then close original body and reset it so caller can read again.
			respBody, rerr := io.ReadAll(resp.Body)
			if rerr != nil {
				lastResp, lastBody, lastErr = resp, nil, wrapErr("read response body", rerr)
				_ = resp.Body.Close()
			} else {
				_ = resp.Body.Close()
				resp.Body = io.NopCloser(bytes.NewReader(respBody))

				// Check expected status codes policy
				if h.isExpectedStatus(resp.StatusCode) {
					return resp, respBody, nil
				}
				// Unexpected status code
				lastResp, lastBody, lastErr = resp, respBody, fmt.Errorf("hook: unexpected status code %d", resp.StatusCode)
			}
		}

		// If we have retries left, wait for backoff (if any) honoring context
		if attempt < max {
			if h.backoff > 0 {
				t := time.NewTimer(h.backoff)
				select {
				case <-t.C:
				case <-ctx.Done():
					t.Stop()
					return lastResp, lastBody, wrapErr("retry wait canceled", ctx.Err())
				}
			}
			continue
		}

		// No more retries
		return lastResp, lastBody, lastErr
	}

	// Should be unreachable
	return nil, nil, errors.New("hook: unexpected execution flow")
}

// renderString renders a single template string with the provided data.
// If strict templates are enabled and a missing key is encountered, an error is returned.
// If the string does not contain "{{", it is returned as-is for performance.
func (h *Hook) renderString(s string, data any) (string, error) {
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
func (h *Hook) renderStringMap(m map[string]string, data any) (map[string]string, error) {
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
func (h *Hook) funcs() template.FuncMap {
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
// under this Hook's configuration.
func (h *Hook) isExpectedStatus(code int) bool {
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
	i := 0
	for i < len(s) {
		// skip spaces
		if s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r' {
			i++
			continue
		}
		// parse integer value
		start := i
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
		if start == i {
			return 0, errors.New("invalid duration: expected number at: " + s[start:])
		}
		numStr := s[start:i]
		// parse unit
		ustart := i
		for i < len(s) && ((s[i] >= 'a' && s[i] <= 'z') || (s[i] >= 'A' && s[i] <= 'Z')) {
			i++
		}
		if ustart == i {
			return 0, errors.New("invalid duration: missing unit after number at: " + s[start:])
		}
		unitStr := strings.ToLower(s[ustart:i])
		mult, ok := units[unitStr]
		if !ok {
			return 0, errors.New("invalid duration: unknown unit " + unitStr)
		}
		// convert numStr to int64
		var val int64
		for j := 0; j < len(numStr); j++ {
			val = val*10 + int64(numStr[j]-'0')
		}
		total += time.Duration(val) * mult
	}
	return total, nil
}

func wrapErr(stage string, err error) error {
	return errors.New("hook: " + stage + ": " + err.Error())
}

func cloneDefaultTransport() *http.Transport {
	// Start from http.DefaultTransport settings
	base, _ := http.DefaultTransport.(*http.Transport)
	if base == nil {
		return &http.Transport{}
	}
	return base.Clone()
}
