//                           _       _
// __      _____  __ ___   ___  __ _| |_ ___
// \ \ /\ / / _ \/ _` \ \ / / |/ _` | __/ _ \
//  \ V  V /  __/ (_| |\ V /| | (_| | ||  __/
//   \_/\_/ \___|\__,_| \_/ |_|\__,_|\__\___|
//
//  Copyright © 2016 - 2024 Weaviate B.V. All rights reserved.
//
//  CONTACT: hello@weaviate.io
//

// Code generated by go-swagger; DO NOT EDIT.

package objects

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

// NewObjectsCreateParams creates a new ObjectsCreateParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewObjectsCreateParams() *ObjectsCreateParams {
	return &ObjectsCreateParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewObjectsCreateParamsWithTimeout creates a new ObjectsCreateParams object
// with the ability to set a timeout on a request.
func NewObjectsCreateParamsWithTimeout(timeout time.Duration) *ObjectsCreateParams {
	return &ObjectsCreateParams{
		timeout: timeout,
	}
}

// NewObjectsCreateParamsWithContext creates a new ObjectsCreateParams object
// with the ability to set a context for a request.
func NewObjectsCreateParamsWithContext(ctx context.Context) *ObjectsCreateParams {
	return &ObjectsCreateParams{
		Context: ctx,
	}
}

// NewObjectsCreateParamsWithHTTPClient creates a new ObjectsCreateParams object
// with the ability to set a custom HTTPClient for a request.
func NewObjectsCreateParamsWithHTTPClient(client *http.Client) *ObjectsCreateParams {
	return &ObjectsCreateParams{
		HTTPClient: client,
	}
}

/*
ObjectsCreateParams contains all the parameters to send to the API endpoint

	for the objects create operation.

	Typically these are written to a http.Request.
*/
type ObjectsCreateParams struct {

	// Body.
	Body *models.Object

	/* ConsistencyLevel.

	   Determines how many replicas must acknowledge a request before it is considered successful
	*/
	ConsistencyLevel *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the objects create params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ObjectsCreateParams) WithDefaults() *ObjectsCreateParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the objects create params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ObjectsCreateParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the objects create params
func (o *ObjectsCreateParams) WithTimeout(timeout time.Duration) *ObjectsCreateParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the objects create params
func (o *ObjectsCreateParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the objects create params
func (o *ObjectsCreateParams) WithContext(ctx context.Context) *ObjectsCreateParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the objects create params
func (o *ObjectsCreateParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the objects create params
func (o *ObjectsCreateParams) WithHTTPClient(client *http.Client) *ObjectsCreateParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the objects create params
func (o *ObjectsCreateParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the objects create params
func (o *ObjectsCreateParams) WithBody(body *models.Object) *ObjectsCreateParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the objects create params
func (o *ObjectsCreateParams) SetBody(body *models.Object) {
	o.Body = body
}

// WithConsistencyLevel adds the consistencyLevel to the objects create params
func (o *ObjectsCreateParams) WithConsistencyLevel(consistencyLevel *string) *ObjectsCreateParams {
	o.SetConsistencyLevel(consistencyLevel)
	return o
}

// SetConsistencyLevel adds the consistencyLevel to the objects create params
func (o *ObjectsCreateParams) SetConsistencyLevel(consistencyLevel *string) {
	o.ConsistencyLevel = consistencyLevel
}

// WriteToRequest writes these params to a swagger request
func (o *ObjectsCreateParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.Body != nil {
		if err := r.SetBodyParam(o.Body); err != nil {
			return err
		}
	}

	if o.ConsistencyLevel != nil {

		// query param consistency_level
		var qrConsistencyLevel string

		if o.ConsistencyLevel != nil {
			qrConsistencyLevel = *o.ConsistencyLevel
		}
		qConsistencyLevel := qrConsistencyLevel
		if qConsistencyLevel != "" {

			if err := r.SetQueryParam("consistency_level", qConsistencyLevel); err != nil {
				return err
			}
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
