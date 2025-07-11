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

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// ShardStatusGetResponse Response body of shard status get request
//
// swagger:model ShardStatusGetResponse
type ShardStatusGetResponse struct {

	// Name of the shard
	Name string `json:"name,omitempty"`

	// Status of the shard
	Status string `json:"status,omitempty"`

	// Size of the vector queue of the shard
	VectorQueueSize int64 `json:"vectorQueueSize"`
}

// Validate validates this shard status get response
func (m *ShardStatusGetResponse) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this shard status get response based on context it is used
func (m *ShardStatusGetResponse) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ShardStatusGetResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ShardStatusGetResponse) UnmarshalBinary(b []byte) error {
	var res ShardStatusGetResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
