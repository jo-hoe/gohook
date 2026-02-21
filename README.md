# gohook

Small dependency-free library to execute configurable, template-driven HTTP webhooks using only the Go standard library.

## Installation

`go get github.com/jo-hoe/gohook@latest`

## Quick start

```go
package main

import (
 "context"
 "fmt"

 "github.com/jo-hoe/gohook/hook"
)

func main() {
 cfg := hook.Config{
  URL:             "https://api.example.com/items?src={{ .Source }}",
  Method:          "POST",
  Headers:         map[string]string{"Authorization": "Bearer {{ .Token }}"},
  Query:           map[string]string{"q": "{{ .Query }}"},
  ContentType:     "application/json",
  Body:            `{"id":"{{ .ID }}","message":"{{ .Message | urlencode }}"}`,
  TimeoutSeconds:  10,
  StrictTemplates: true,
  ExpectedStatus:  []int{200, 201},
  MaxRetries:      3,
  Backoff:         "30s",
 }

 h, err := hook.New(cfg)
 if err != nil {
  panic(err)
 }

 resp, respBody, err := h.Execute(context.Background(), map[string]any{
  "Source":  "gohook",
  "Token":   "abc123",
  "Query":   "search term",
  "ID":      "42",
  "Message": "hello world",
 })
 if err != nil {
  panic(err)
 }

 fmt.Println("status:", resp.Status)
 fmt.Println("body bytes:", len(respBody))
}
```

## Configuration

All string fields support Go text/template placeholders ({{ ... }}), resolved at Execute time against the provided data object.

- URL: target endpoint. May include template placeholders.
- Method: HTTP method (GET, POST, PUT, PATCH, DELETE, ...).
  - Default: POST when Body is non-empty, otherwise GET.
- Headers: request headers. Keys and values may contain templates.
- Query: query parameters to be added to the URL. Keys and values may contain templates. Merged with URL’s existing query.
- Body: request body as a string (after templating). Optional.
- ContentType: applied if set and “Content-Type” header not already provided by Headers. May contain templates.
- TimeoutSeconds: timeout applied to the default HTTP client created by New (0 means use http.Client default). Ignored if a custom client is supplied via options.
- InsecureSkipVerify: disables TLS certificate verification for the default client when true. Ignored if a custom client is supplied.
- StrictTemplates: controls missing key behavior in templates:
  - true: missing template variables cause an error (missingkey=error)
  - false: missing variables render as <no value> (missingkey=default)
- ExpectedStatus: acceptable HTTP response status codes. When non-empty, any code not in this list is considered unexpected and will trigger retries (up to MaxRetries).
- MaxRetries: number of retry attempts on transport errors or unexpected status codes. 0 means no retries (single attempt).
- Backoff: delay between retries, parsed in a Kubernetes-style duration. Examples:
  - "24s", "3m", "1h30m", "4d", "1w", "3m 4d"
  - When empty, no delay between attempts.
  - Invalid values cause New to return an error.

## Options

Functional options to customize Hook behavior:

- WithHTTPClient(c *http.Client):
  - Provide a custom http.Client. When provided, TimeoutSeconds and InsecureSkipVerify from Config are not applied.
- WithTimeout(d time.Duration):
  - Overrides Config.TimeoutSeconds using a time.Duration for the client timeout.
- WithStrictTemplates(strict bool):
  - Overrides Config.StrictTemplates.
- WithInsecureSkipVerify(insecure bool):
  - Enables/disables TLS verification on the default client. Ignored if a custom client is provided (best-effort applied if possible).

## Template helpers

Available functions inside templates (dependency-free):

- json: json-encode a value to a string — {{ json .Value }}
- urlencode: URL query escaping — {{ .Text | urlencode }}
- lower, upper, trim: simple string transforms — {{ .Name | lower }}
- join: join string slices — {{ join .Slice "," }}

Example:

- Body: `{"id":"{{ .ID }}","message":"{{ .Message | urlencode }}"}`

## Execution semantics

- Execute(ctx, data) renders all templated fields and performs the HTTP request.
- Returns:
  - http.Response with Body reset to a fresh reader of the returned bytes
  - response body bytes
  - error if any step fails
- Status handling:
  - By default, non-2xx responses are not treated as errors (caller decides).
  - When ExpectedStatus is set, any status not listed is “unexpected” and will trigger retries up to MaxRetries with Backoff delay.
- Retries:
  - Triggered by transport errors and unexpected status codes (per ExpectedStatus).
  - Delay between retries respects Backoff; context cancellation aborts waiting and execution.

## Concurrency

- Hook is safe for concurrent use if the provided http.Client is safe for concurrent use (the default http.Client is).

## Security note

- InsecureSkipVerify disables TLS certificate verification. Use only if you understand the risks (e.g., for testing with self-signed certs).
