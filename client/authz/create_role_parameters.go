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

package authz

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

// NewCreateRoleParams creates a new CreateRoleParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewCreateRoleParams() *CreateRoleParams {
	return &CreateRoleParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewCreateRoleParamsWithTimeout creates a new CreateRoleParams object
// with the ability to set a timeout on a request.
func NewCreateRoleParamsWithTimeout(timeout time.Duration) *CreateRoleParams {
	return &CreateRoleParams{
		timeout: timeout,
	}
}

// NewCreateRoleParamsWithContext creates a new CreateRoleParams object
// with the ability to set a context for a request.
func NewCreateRoleParamsWithContext(ctx context.Context) *CreateRoleParams {
	return &CreateRoleParams{
		Context: ctx,
	}
}

// NewCreateRoleParamsWithHTTPClient creates a new CreateRoleParams object
// with the ability to set a custom HTTPClient for a request.
func NewCreateRoleParamsWithHTTPClient(client *http.Client) *CreateRoleParams {
	return &CreateRoleParams{
		HTTPClient: client,
	}
}

/*
CreateRoleParams contains all the parameters to send to the API endpoint

	for the create role operation.

	Typically these are written to a http.Request.
*/
type CreateRoleParams struct {

	// Body.
	Body *models.Role

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the create role params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreateRoleParams) WithDefaults() *CreateRoleParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the create role params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreateRoleParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the create role params
func (o *CreateRoleParams) WithTimeout(timeout time.Duration) *CreateRoleParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the create role params
func (o *CreateRoleParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the create role params
func (o *CreateRoleParams) WithContext(ctx context.Context) *CreateRoleParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the create role params
func (o *CreateRoleParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the create role params
func (o *CreateRoleParams) WithHTTPClient(client *http.Client) *CreateRoleParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the create role params
func (o *CreateRoleParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the create role params
func (o *CreateRoleParams) WithBody(body *models.Role) *CreateRoleParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the create role params
func (o *CreateRoleParams) SetBody(body *models.Role) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *CreateRoleParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
