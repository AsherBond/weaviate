//                           _       _
// __      _____  __ ___   ___  __ _| |_ ___
// \ \ /\ / / _ \/ _` \ \ / / |/ _` | __/ _ \
//  \ V  V /  __/ (_| |\ V /| | (_| | ||  __/
//   \_/\_/ \___|\__,_| \_/ |_|\__,_|\__\___|
//
//  Copyright © 2016 - 2025 Weaviate B.V. All rights reserved.
//
//  CONTACT: hello@weaviate.io
//

// Code generated by go-swagger; DO NOT EDIT.

package backups

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
)

// NewBackupsListParams creates a new BackupsListParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewBackupsListParams() *BackupsListParams {
	return &BackupsListParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewBackupsListParamsWithTimeout creates a new BackupsListParams object
// with the ability to set a timeout on a request.
func NewBackupsListParamsWithTimeout(timeout time.Duration) *BackupsListParams {
	return &BackupsListParams{
		timeout: timeout,
	}
}

// NewBackupsListParamsWithContext creates a new BackupsListParams object
// with the ability to set a context for a request.
func NewBackupsListParamsWithContext(ctx context.Context) *BackupsListParams {
	return &BackupsListParams{
		Context: ctx,
	}
}

// NewBackupsListParamsWithHTTPClient creates a new BackupsListParams object
// with the ability to set a custom HTTPClient for a request.
func NewBackupsListParamsWithHTTPClient(client *http.Client) *BackupsListParams {
	return &BackupsListParams{
		HTTPClient: client,
	}
}

/*
BackupsListParams contains all the parameters to send to the API endpoint

	for the backups list operation.

	Typically these are written to a http.Request.
*/
type BackupsListParams struct {

	/* Backend.

	   Backup backend name e.g. filesystem, gcs, s3.
	*/
	Backend string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the backups list params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *BackupsListParams) WithDefaults() *BackupsListParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the backups list params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *BackupsListParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the backups list params
func (o *BackupsListParams) WithTimeout(timeout time.Duration) *BackupsListParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the backups list params
func (o *BackupsListParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the backups list params
func (o *BackupsListParams) WithContext(ctx context.Context) *BackupsListParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the backups list params
func (o *BackupsListParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the backups list params
func (o *BackupsListParams) WithHTTPClient(client *http.Client) *BackupsListParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the backups list params
func (o *BackupsListParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBackend adds the backend to the backups list params
func (o *BackupsListParams) WithBackend(backend string) *BackupsListParams {
	o.SetBackend(backend)
	return o
}

// SetBackend adds the backend to the backups list params
func (o *BackupsListParams) SetBackend(backend string) {
	o.Backend = backend
}

// WriteToRequest writes these params to a swagger request
func (o *BackupsListParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param backend
	if err := r.SetPathParam("backend", o.Backend); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
