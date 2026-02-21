package goback

import (
	"context"
	"net/http"
)

// TemplateData provides a strongly-typed wrapper for selector values
// that are made available to goback templates as {{ .<Key> }}.
type TemplateData struct {
	Values map[string]string
}

// CallbackExecutor defines a simple, strongly-typed interface to execute an HTTP callback
// using goback under the hood.
// To send multipart/form-data with in-memory attachments, set Config.Multipart
// when constructing the CallbackExecutor via NewCallbackExecutor, then call Execute.
// Callback will detect Config.Multipart and build the multipart body automatically.
type CallbackExecutor interface {
	// Execute evaluates templates against the provided data and performs the HTTP request.
	// It returns the underlying http.Response (if any), the response body bytes, and an error if execution fails.
	Execute(ctx context.Context, data TemplateData) (*http.Response, []byte, error)
}

type callbackExecutor struct {
	h *Callback
}

// NewCallbackExecutor constructs a CallbackExecutor from a Config.
// If client is non-nil, it will be used via WithHTTPClient; otherwise goback will create its own client
// honoring Timeout and InsecureSkipVerify from the config.
func NewCallbackExecutor(cfg Config, client *http.Client) (CallbackExecutor, error) {
	var (
		h   *Callback
		err error
	)
	if client != nil {
		h, err = New(cfg, WithHTTPClient(client))
	} else {
		h, err = New(cfg)
	}
	if err != nil {
		return nil, err
	}
	return &callbackExecutor{h: h}, nil
}

func (e *callbackExecutor) Execute(ctx context.Context, data TemplateData) (*http.Response, []byte, error) {
	payload := make(map[string]any, len(data.Values))
	for k, v := range data.Values {
		payload[k] = v
	}
	return e.h.Execute(ctx, payload)
}