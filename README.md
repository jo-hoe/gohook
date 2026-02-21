# goback

[![Test Status](https://github.com/jo-hoe/goback/workflows/test/badge.svg)](https://github.com/jo-hoe/goback/actions?workflow=test)
[![Lint Status](https://github.com/jo-hoe/goback/workflows/lint/badge.svg)](https://github.com/jo-hoe/goback/actions?workflow=lint)
[![Go Report Card](https://goreportcard.com/badge/github.com/jo-hoe/goback)](https://goreportcard.com/report/github.com/jo-hoe/goback)
[![Coverage Status](https://coveralls.io/repos/github/jo-hoe/goback/badge.svg?branch=main)](https://coveralls.io/github/jo-hoe/goback?branch=main)

Small dependency-free library to execute configurable, template-driven HTTP callbacks using only the Go standard library.

## Installation

`go get github.com/jo-hoe/goback@latest`

## Quick start

```go
package main

import (
	"context"
	"fmt"

	"github.com/jo-hoe/goback"
)

func main() {
	cfg := goback.Config{
		URL:             "https://api.example.com/items?src={{ .Source }}",
		Method:          "POST",
		Headers:         map[string]string{"Authorization": "Bearer {{ .Token }}"},
		Query:           map[string]string{"q": "{{ .Query }}"},
		ContentType:     "application/json",
		Body:            `{"id":"{{ .ID }}","message":"{{ .Message | urlencode }}"}`,
		Timeout:         "10s",
		StrictTemplates: true,
		ExpectedStatus:  []int{200, 201},
		MaxRetries:      3,
		Backoff:         "30s",
	}

	cb, err := goback.New(cfg)
	if err != nil {
		panic(err)
	}

	resp, respBody, err := cb.Execute(context.Background(), map[string]any{
		"Source":  "goback",
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

## CallbackExecutor (typed helper)

If you prefer a small, strongly-typed wrapper over Callback, use CallbackExecutor.
It accepts TemplateData (map[string]string) and optionally a custom *http.Client.
Internally, NewCallbackExecutor constructs a Callback and, when a client is provided, uses it via WithHTTPClient.
If no client is provided, goback builds a default client honoring Timeout and InsecureSkipVerify in the Config.

Example:

```go
package main

import (
  "context"
  "fmt"
  "net/http"

  "github.com/jo-hoe/goback"
)

func main() {
  cfg := goback.Config{
    URL:            "https://api.example.com/items/{{ .ID }}?src={{ .Source }}",
    Headers:        map[string]string{"Authorization": "Bearer {{ .Token }}"},
    ContentType:    "application/json",
    Body:           `{"message":"{{ .Message | urlencode }}"}`,
    Timeout:        "10s",
    ExpectedStatus: []int{200, 201},
  }

  // Pass a custom client or nil to let goback create one from cfg
  var client *http.Client = nil
  exec, err := goback.NewCallbackExecutor(cfg, client)
  if err != nil {
    panic(err)
  }

  resp, body, err := exec.Execute(context.Background(), goback.TemplateData{
    Values: map[string]string{
      "ID":      "42",
      "Source":  "goback",
      "Token":   "abc123",
      "Message": "hello world",
    },
  })
  if err != nil {
    panic(err)
  }
  fmt.Println("status:", resp.Status)
  fmt.Println("body bytes:", len(body))
}
```

Notes:

- TemplateData values are exposed to templates as {{ .<Key> }}.
- Execute returns the underlying *http.Response and response body bytes, similar to Callback.Execute.
- When a custom *http.Client is provided, Config.Timeout and Config.InsecureSkipVerify are ignored (the client is used as-is).

## Multipart form-data (attachments via in-memory bytes)

Use multipart/form-data to send regular form fields and file attachments from in-memory bytes by configuring Config.Multipart. Then call Execute as usual (either via Callback or CallbackExecutor). No separate ExecuteMultipart function is needed.

### Types

- Multipart:
  - Fields: map[string]string — normal form fields (keys and values templated)
  - Files: []ByteFile — in-memory file attachments
- ByteFile:
  - Field: string — form field name (templated)
  - FileName: string — filename sent to server (templated; defaults to "file" when empty)
  - ContentType: string — optional per-file content type (templated)
  - Data: []byte — file content in memory

### Behavior

- Content-Type is set automatically with a generated boundary for multipart requests (overrides any Content-Type header for this request).
- Method defaulting: if Config.Method is empty and either Body is non-empty or Multipart is set, the default method is POST; otherwise GET.
- Templates: field names, field values, file field names, file names, and per-file content types support Go text/template placeholders and StrictTemplates behavior.

#### Example (Callback)

```go
cfg := goback.Config{
  URL:            "https://example.com/upload?src={{ .Source }}",
  Headers:        map[string]string{"Authorization": "Bearer {{ .Token }}"},
  ExpectedStatus: []int{201},
  Multipart: &goback.Multipart{
    Fields: map[string]string{
      "title": "{{ .Title }}",
      "note":  "{{ .Note }}",
    },
    Files: []goback.ByteFile{
      {
        Field:       "file",
        FileName:    "report-{{ .Quarter }}.pdf",
        ContentType: "application/pdf",
        Data:        []byte("%PDF-FAKE%"),
      },
    },
  },
}
cb, err := goback.New(cfg)
if err != nil {
  panic(err)
}
resp, body, err := cb.Execute(context.Background(), map[string]any{
  "Source":  "goback",
  "Token":   "abc123",
  "Title":   "Report",
  "Note":    "Please review",
  "Quarter": "Q1",
})
```

#### Example (CallbackExecutor typed helper)

```go
exec, err := goback.NewCallbackExecutor(goback.Config{
  URL:            "https://example.com/typed?src={{ .source }}",
  Headers:        map[string]string{"X-Req": "{{ .reqid }}"},
  ExpectedStatus: []int{200},
  Multipart: &goback.Multipart{
    Fields: map[string]string{"a": "{{ .a }}", "b": "{{ .b }}"},
    Files:  []goback.ByteFile{{ Field: "file", FileName: "x.txt", Data: []byte("hello") }},
  },
}, nil)
if err != nil {
  panic(err)
}
resp, body, err := exec.Execute(context.Background(), goback.TemplateData{
  Values: map[string]string{"source": "typed", "reqid": "r123", "a": "1", "b": "2"},
})
```

Caveat (memory buffering):

- Multipart bodies are assembled entirely in memory before the request is sent. Very large files will increase memory usage accordingly. Streaming file parts is not currently supported.
- If you need streaming for very large attachments, open an issue; the API can be extended to stream parts without buffering the full body.

## Configuration

All string fields support Go text/template placeholders ({{ ... }}), resolved at Execute time against the provided data object.

| Field              | Type/Default                                       | Description |
| ------------------ | -------------------------------------------------- | ----------- |
| URL                | string                                             | Target endpoint. May include template placeholders. |
| Method             | string (default: POST if Body non-empty, else GET) | HTTP method (GET, POST, PUT, PATCH, DELETE, ...). |
| Headers            | map[string]string                                  | Request headers. Keys and values may contain templates. |
| Query              | map[string]string                                  | Query parameters to be added to the URL. Keys and values may contain templates. Merged with URL’s existing query. |
| Body               | string (optional)                                  | Request body as a string (after templating). |
| ContentType        | string                                             | Applied if set and "Content-Type" header not already provided by Headers. May contain templates. |
| Timeout            | string (K8s-style duration; empty uses http.Client default) | Timeout applied to the default HTTP client created by New. Parsed like "10s", "3m", "1h30m", "4d". Ignored if a custom client is supplied via options. |
| InsecureSkipVerify | bool                                               | Disables TLS certificate verification for the default client when true. Ignored if a custom client is supplied. |
| StrictTemplates    | bool                                               | Controls missing key behavior in templates: true → error (missingkey=error); false → render as <no value> (missingkey=default). |
| ExpectedStatus     | []int                                              | Acceptable HTTP response status codes. When non-empty, any code not in this list is considered unexpected and will trigger retries (up to MaxRetries). |
| MaxRetries         | int (0 = no retries; single attempt)               | Number of retry attempts on transport errors or unexpected status codes. |
| Backoff            | duration string                                    | Delay between retries, parsed in a Kubernetes-style duration. Examples: "24s", "3m", "1h30m", "4d", "1w", "3m 4d". When empty, no delay between attempts. Invalid values cause New to return an error. |

## Options

Functional options to customize Callback behavior:

| Option                               | Purpose                                | Notes |
| ------------------------------------ | -------------------------------------- | ----- |
| WithHTTPClient(c *http.Client)       | Provide a custom http.Client           | When provided, Timeout and InsecureSkipVerify from Config are not applied. |
| WithTimeout(d time.Duration)         | Override client timeout                | Overrides Config.Timeout using a time.Duration for the client timeout. |
| WithStrictTemplates(strict bool)     | Control missing key behavior           | Overrides Config.StrictTemplates. |
| WithInsecureSkipVerify(insecure bool)| Toggle TLS verification on default client | Ignored if a custom client is provided (best-effort applied if possible). |

## Template helpers

Available functions inside templates (dependency-free):

| Function  | Description                     | Example                 |
| --------- | -------------------------------- | ----------------------- |
| json      | JSON-encode a value to a string  | {{ json .Value }}       |
| urlencode | URL query escaping               | {{ .Text \| urlencode }} |
| lower     | Lowercase a string               | {{ .Name \| lower }}     |
| upper     | Uppercase a string               | {{ .Name \| upper }}     |
| trim      | Trim surrounding whitespace      | {{ .Name \| trim }}      |
| join      | Join string slices               | {{ join .Slice "," }}    |

Example:

- Body: `{"id":"{{ .ID }}","message":"{{ .Message | urlencode }}"}`

## Concurrency

- Callback is safe for concurrent use if the provided http.Client is safe for concurrent use (the default http.Client is).

## Security note

- InsecureSkipVerify disables TLS certificate verification. Use only if you understand the risks (e.g., for testing with self-signed certs).