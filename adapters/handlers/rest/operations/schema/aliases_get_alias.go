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

package schema

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"

	"github.com/go-openapi/runtime/middleware"

	"github.com/weaviate/weaviate/entities/models"
)

// AliasesGetAliasHandlerFunc turns a function with the right signature into a aliases get alias handler
type AliasesGetAliasHandlerFunc func(AliasesGetAliasParams, *models.Principal) middleware.Responder

// Handle executing the request and returning a response
func (fn AliasesGetAliasHandlerFunc) Handle(params AliasesGetAliasParams, principal *models.Principal) middleware.Responder {
	return fn(params, principal)
}

// AliasesGetAliasHandler interface for that can handle valid aliases get alias params
type AliasesGetAliasHandler interface {
	Handle(AliasesGetAliasParams, *models.Principal) middleware.Responder
}

// NewAliasesGetAlias creates a new http.Handler for the aliases get alias operation
func NewAliasesGetAlias(ctx *middleware.Context, handler AliasesGetAliasHandler) *AliasesGetAlias {
	return &AliasesGetAlias{Context: ctx, Handler: handler}
}

/*
	AliasesGetAlias swagger:route GET /aliases/{aliasName} schema aliasesGetAlias

# Get aliases

get all aliases or filtered by a class (collection)
*/
type AliasesGetAlias struct {
	Context *middleware.Context
	Handler AliasesGetAliasHandler
}

func (o *AliasesGetAlias) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		*r = *rCtx
	}
	var Params = NewAliasesGetAliasParams()
	uprinc, aCtx, err := o.Context.Authorize(r, route)
	if err != nil {
		o.Context.Respond(rw, r, route.Produces, route, err)
		return
	}
	if aCtx != nil {
		*r = *aCtx
	}
	var principal *models.Principal
	if uprinc != nil {
		principal = uprinc.(*models.Principal) // this is really a models.Principal, I promise
	}

	if err := o.Context.BindValidRequest(r, route, &Params); err != nil { // bind params
		o.Context.Respond(rw, r, route.Produces, route, err)
		return
	}

	res := o.Handler.Handle(Params, principal) // actually handle the request
	o.Context.Respond(rw, r, route.Produces, route, res)

}
