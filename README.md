# gohook

[![Test Status](https://github.com/jo-hoe/gohook/workflows/test/badge.svg)](https://github.com/jo-hoe/gohook/actions?workflow=test)
[![Lint Status](https://github.com/jo-hoe/gohook/workflows/lint/badge.svg)](https://github.com/jo-hoe/gohook/actions?workflow=lint)
[![Go Report Card](https://goreportcard.com/badge/github.com/jo-hoe/gohook)](https://goreportcard.com/report/github.com/jo-hoe/gohook)
[![Coverage Status](https://coveralls.io/repos/github/jo-hoe/gohook/badge.svg?branch=main)](https://coveralls.io/github/jo-hoe/gohook?branch=main)

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

| Field              | Type/Default                                       | Description |
| ------------------ | -------------------------------------------------- | ----------- |
| URL                | string                                             | Target endpoint. May include template placeholders. |
| Method             | string (default: POST if Body non-empty, else GET) | HTTP method (GET, POST, PUT, PATCH, DELETE, ...). |
| Headers            | map[string]string                                  | Request headers. Keys and values may contain templates. |
| Query              | map[string]string                                  | Query parameters to be added to the URL. Keys and values may contain templates. Merged with URL’s existing query. |
| Body               | string (optional)                                  | Request body as a string (after templating). |
| ContentType        | string                                             | Applied if set and "Content-Type" header not already provided by Headers. May contain templates. |
| TimeoutSeconds     | int (0 uses http.Client default)                   | Timeout applied to the default HTTP client created by New. Ignored if a custom client is supplied via options. |
| InsecureSkipVerify | bool                                               | Disables TLS certificate verification for the default client when true. Ignored if a custom client is supplied. |
| StrictTemplates    | bool                                               | Controls missing key behavior in templates: true → error (missingkey=error); false → render as <no value> (missingkey=default). |
| ExpectedStatus     | []int                                              | Acceptable HTTP response status codes. When non-empty, any code not in this list is considered unexpected and will trigger retries (up to MaxRetries). |
| MaxRetries         | int (0 = no retries; single attempt)               | Number of retry attempts on transport errors or unexpected status codes. |
| Backoff            | duration string                                    | Delay between retries, parsed in a Kubernetes-style duration. Examples: "24s", "3m", "1h30m", "4d", "1w", "3m 4d". When empty, no delay between attempts. Invalid values cause New to return an error. |

## Options

Functional options to customize Hook behavior:

| Option                               | Purpose                                | Notes |
| ------------------------------------ | -------------------------------------- | ----- |
| WithHTTPClient(c *http.Client)       | Provide a custom http.Client           | When provided, TimeoutSeconds and InsecureSkipVerify from Config are not applied. |
| WithTimeout(d time.Duration)         | Override client timeout                | Overrides Config.TimeoutSeconds using a time.Duration for the client timeout. |
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

- Hook is safe for concurrent use if the provided http.Client is safe for concurrent use (the default http.Client is).

## Security note

- InsecureSkipVerify disables TLS certificate verification. Use only if you understand the risks (e.g., for testing with self-signed certs).
