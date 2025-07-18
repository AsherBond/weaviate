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

package replication

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

	"github.com/weaviate/weaviate/entities/models"
)

// NewForceDeleteReplicationsParams creates a new ForceDeleteReplicationsParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewForceDeleteReplicationsParams() *ForceDeleteReplicationsParams {
	return &ForceDeleteReplicationsParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewForceDeleteReplicationsParamsWithTimeout creates a new ForceDeleteReplicationsParams object
// with the ability to set a timeout on a request.
func NewForceDeleteReplicationsParamsWithTimeout(timeout time.Duration) *ForceDeleteReplicationsParams {
	return &ForceDeleteReplicationsParams{
		timeout: timeout,
	}
}

// NewForceDeleteReplicationsParamsWithContext creates a new ForceDeleteReplicationsParams object
// with the ability to set a context for a request.
func NewForceDeleteReplicationsParamsWithContext(ctx context.Context) *ForceDeleteReplicationsParams {
	return &ForceDeleteReplicationsParams{
		Context: ctx,
	}
}

// NewForceDeleteReplicationsParamsWithHTTPClient creates a new ForceDeleteReplicationsParams object
// with the ability to set a custom HTTPClient for a request.
func NewForceDeleteReplicationsParamsWithHTTPClient(client *http.Client) *ForceDeleteReplicationsParams {
	return &ForceDeleteReplicationsParams{
		HTTPClient: client,
	}
}

/*
ForceDeleteReplicationsParams contains all the parameters to send to the API endpoint

	for the force delete replications operation.

	Typically these are written to a http.Request.
*/
type ForceDeleteReplicationsParams struct {

	// Body.
	Body *models.ReplicationReplicateForceDeleteRequest

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the force delete replications params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ForceDeleteReplicationsParams) WithDefaults() *ForceDeleteReplicationsParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the force delete replications params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ForceDeleteReplicationsParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the force delete replications params
func (o *ForceDeleteReplicationsParams) WithTimeout(timeout time.Duration) *ForceDeleteReplicationsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the force delete replications params
func (o *ForceDeleteReplicationsParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the force delete replications params
func (o *ForceDeleteReplicationsParams) WithContext(ctx context.Context) *ForceDeleteReplicationsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the force delete replications params
func (o *ForceDeleteReplicationsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the force delete replications params
func (o *ForceDeleteReplicationsParams) WithHTTPClient(client *http.Client) *ForceDeleteReplicationsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the force delete replications params
func (o *ForceDeleteReplicationsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the force delete replications params
func (o *ForceDeleteReplicationsParams) WithBody(body *models.ReplicationReplicateForceDeleteRequest) *ForceDeleteReplicationsParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the force delete replications params
func (o *ForceDeleteReplicationsParams) SetBody(body *models.ReplicationReplicateForceDeleteRequest) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *ForceDeleteReplicationsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.Body != nil {
		if err := r.SetBodyParam(o.Body); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
