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

package objects

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/weaviate/weaviate/entities/models"
)

// ObjectsClassDeleteReader is a Reader for the ObjectsClassDelete structure.
type ObjectsClassDeleteReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ObjectsClassDeleteReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewObjectsClassDeleteNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewObjectsClassDeleteBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewObjectsClassDeleteUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewObjectsClassDeleteForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewObjectsClassDeleteNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 422:
		result := NewObjectsClassDeleteUnprocessableEntity()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewObjectsClassDeleteInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewObjectsClassDeleteNoContent creates a ObjectsClassDeleteNoContent with default headers values
func NewObjectsClassDeleteNoContent() *ObjectsClassDeleteNoContent {
	return &ObjectsClassDeleteNoContent{}
}

/*
ObjectsClassDeleteNoContent describes a response with status code 204, with default header values.

Successfully deleted.
*/
type ObjectsClassDeleteNoContent struct {
}

// IsSuccess returns true when this objects class delete no content response has a 2xx status code
func (o *ObjectsClassDeleteNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this objects class delete no content response has a 3xx status code
func (o *ObjectsClassDeleteNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this objects class delete no content response has a 4xx status code
func (o *ObjectsClassDeleteNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this objects class delete no content response has a 5xx status code
func (o *ObjectsClassDeleteNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this objects class delete no content response a status code equal to that given
func (o *ObjectsClassDeleteNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the objects class delete no content response
func (o *ObjectsClassDeleteNoContent) Code() int {
	return 204
}

func (o *ObjectsClassDeleteNoContent) Error() string {
	return fmt.Sprintf("[DELETE /objects/{className}/{id}][%d] objectsClassDeleteNoContent ", 204)
}

func (o *ObjectsClassDeleteNoContent) String() string {
	return fmt.Sprintf("[DELETE /objects/{className}/{id}][%d] objectsClassDeleteNoContent ", 204)
}

func (o *ObjectsClassDeleteNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewObjectsClassDeleteBadRequest creates a ObjectsClassDeleteBadRequest with default headers values
func NewObjectsClassDeleteBadRequest() *ObjectsClassDeleteBadRequest {
	return &ObjectsClassDeleteBadRequest{}
}

/*
ObjectsClassDeleteBadRequest describes a response with status code 400, with default header values.

Malformed request.
*/
type ObjectsClassDeleteBadRequest struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this objects class delete bad request response has a 2xx status code
func (o *ObjectsClassDeleteBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this objects class delete bad request response has a 3xx status code
func (o *ObjectsClassDeleteBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this objects class delete bad request response has a 4xx status code
func (o *ObjectsClassDeleteBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this objects class delete bad request response has a 5xx status code
func (o *ObjectsClassDeleteBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this objects class delete bad request response a status code equal to that given
func (o *ObjectsClassDeleteBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the objects class delete bad request response
func (o *ObjectsClassDeleteBadRequest) Code() int {
	return 400
}

func (o *ObjectsClassDeleteBadRequest) Error() string {
	return fmt.Sprintf("[DELETE /objects/{className}/{id}][%d] objectsClassDeleteBadRequest  %+v", 400, o.Payload)
}

func (o *ObjectsClassDeleteBadRequest) String() string {
	return fmt.Sprintf("[DELETE /objects/{className}/{id}][%d] objectsClassDeleteBadRequest  %+v", 400, o.Payload)
}

func (o *ObjectsClassDeleteBadRequest) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *ObjectsClassDeleteBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewObjectsClassDeleteUnauthorized creates a ObjectsClassDeleteUnauthorized with default headers values
func NewObjectsClassDeleteUnauthorized() *ObjectsClassDeleteUnauthorized {
	return &ObjectsClassDeleteUnauthorized{}
}

/*
ObjectsClassDeleteUnauthorized describes a response with status code 401, with default header values.

Unauthorized or invalid credentials.
*/
type ObjectsClassDeleteUnauthorized struct {
}

// IsSuccess returns true when this objects class delete unauthorized response has a 2xx status code
func (o *ObjectsClassDeleteUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this objects class delete unauthorized response has a 3xx status code
func (o *ObjectsClassDeleteUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this objects class delete unauthorized response has a 4xx status code
func (o *ObjectsClassDeleteUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this objects class delete unauthorized response has a 5xx status code
func (o *ObjectsClassDeleteUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this objects class delete unauthorized response a status code equal to that given
func (o *ObjectsClassDeleteUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the objects class delete unauthorized response
func (o *ObjectsClassDeleteUnauthorized) Code() int {
	return 401
}

func (o *ObjectsClassDeleteUnauthorized) Error() string {
	return fmt.Sprintf("[DELETE /objects/{className}/{id}][%d] objectsClassDeleteUnauthorized ", 401)
}

func (o *ObjectsClassDeleteUnauthorized) String() string {
	return fmt.Sprintf("[DELETE /objects/{className}/{id}][%d] objectsClassDeleteUnauthorized ", 401)
}

func (o *ObjectsClassDeleteUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewObjectsClassDeleteForbidden creates a ObjectsClassDeleteForbidden with default headers values
func NewObjectsClassDeleteForbidden() *ObjectsClassDeleteForbidden {
	return &ObjectsClassDeleteForbidden{}
}

/*
ObjectsClassDeleteForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type ObjectsClassDeleteForbidden struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this objects class delete forbidden response has a 2xx status code
func (o *ObjectsClassDeleteForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this objects class delete forbidden response has a 3xx status code
func (o *ObjectsClassDeleteForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this objects class delete forbidden response has a 4xx status code
func (o *ObjectsClassDeleteForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this objects class delete forbidden response has a 5xx status code
func (o *ObjectsClassDeleteForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this objects class delete forbidden response a status code equal to that given
func (o *ObjectsClassDeleteForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the objects class delete forbidden response
func (o *ObjectsClassDeleteForbidden) Code() int {
	return 403
}

func (o *ObjectsClassDeleteForbidden) Error() string {
	return fmt.Sprintf("[DELETE /objects/{className}/{id}][%d] objectsClassDeleteForbidden  %+v", 403, o.Payload)
}

func (o *ObjectsClassDeleteForbidden) String() string {
	return fmt.Sprintf("[DELETE /objects/{className}/{id}][%d] objectsClassDeleteForbidden  %+v", 403, o.Payload)
}

func (o *ObjectsClassDeleteForbidden) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *ObjectsClassDeleteForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewObjectsClassDeleteNotFound creates a ObjectsClassDeleteNotFound with default headers values
func NewObjectsClassDeleteNotFound() *ObjectsClassDeleteNotFound {
	return &ObjectsClassDeleteNotFound{}
}

/*
ObjectsClassDeleteNotFound describes a response with status code 404, with default header values.

Successful query result but no resource was found.
*/
type ObjectsClassDeleteNotFound struct {
}

// IsSuccess returns true when this objects class delete not found response has a 2xx status code
func (o *ObjectsClassDeleteNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this objects class delete not found response has a 3xx status code
func (o *ObjectsClassDeleteNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this objects class delete not found response has a 4xx status code
func (o *ObjectsClassDeleteNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this objects class delete not found response has a 5xx status code
func (o *ObjectsClassDeleteNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this objects class delete not found response a status code equal to that given
func (o *ObjectsClassDeleteNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the objects class delete not found response
func (o *ObjectsClassDeleteNotFound) Code() int {
	return 404
}

func (o *ObjectsClassDeleteNotFound) Error() string {
	return fmt.Sprintf("[DELETE /objects/{className}/{id}][%d] objectsClassDeleteNotFound ", 404)
}

func (o *ObjectsClassDeleteNotFound) String() string {
	return fmt.Sprintf("[DELETE /objects/{className}/{id}][%d] objectsClassDeleteNotFound ", 404)
}

func (o *ObjectsClassDeleteNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewObjectsClassDeleteUnprocessableEntity creates a ObjectsClassDeleteUnprocessableEntity with default headers values
func NewObjectsClassDeleteUnprocessableEntity() *ObjectsClassDeleteUnprocessableEntity {
	return &ObjectsClassDeleteUnprocessableEntity{}
}

/*
ObjectsClassDeleteUnprocessableEntity describes a response with status code 422, with default header values.

Request is well-formed (i.e., syntactically correct), but erroneous.
*/
type ObjectsClassDeleteUnprocessableEntity struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this objects class delete unprocessable entity response has a 2xx status code
func (o *ObjectsClassDeleteUnprocessableEntity) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this objects class delete unprocessable entity response has a 3xx status code
func (o *ObjectsClassDeleteUnprocessableEntity) IsRedirect() bool {
	return false
}

// IsClientError returns true when this objects class delete unprocessable entity response has a 4xx status code
func (o *ObjectsClassDeleteUnprocessableEntity) IsClientError() bool {
	return true
}

// IsServerError returns true when this objects class delete unprocessable entity response has a 5xx status code
func (o *ObjectsClassDeleteUnprocessableEntity) IsServerError() bool {
	return false
}

// IsCode returns true when this objects class delete unprocessable entity response a status code equal to that given
func (o *ObjectsClassDeleteUnprocessableEntity) IsCode(code int) bool {
	return code == 422
}

// Code gets the status code for the objects class delete unprocessable entity response
func (o *ObjectsClassDeleteUnprocessableEntity) Code() int {
	return 422
}

func (o *ObjectsClassDeleteUnprocessableEntity) Error() string {
	return fmt.Sprintf("[DELETE /objects/{className}/{id}][%d] objectsClassDeleteUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *ObjectsClassDeleteUnprocessableEntity) String() string {
	return fmt.Sprintf("[DELETE /objects/{className}/{id}][%d] objectsClassDeleteUnprocessableEntity  %+v", 422, o.Payload)
}

func (o *ObjectsClassDeleteUnprocessableEntity) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *ObjectsClassDeleteUnprocessableEntity) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewObjectsClassDeleteInternalServerError creates a ObjectsClassDeleteInternalServerError with default headers values
func NewObjectsClassDeleteInternalServerError() *ObjectsClassDeleteInternalServerError {
	return &ObjectsClassDeleteInternalServerError{}
}

/*
ObjectsClassDeleteInternalServerError describes a response with status code 500, with default header values.

An error has occurred while trying to fulfill the request. Most likely the ErrorResponse will contain more information about the error.
*/
type ObjectsClassDeleteInternalServerError struct {
	Payload *models.ErrorResponse
}

// IsSuccess returns true when this objects class delete internal server error response has a 2xx status code
func (o *ObjectsClassDeleteInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this objects class delete internal server error response has a 3xx status code
func (o *ObjectsClassDeleteInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this objects class delete internal server error response has a 4xx status code
func (o *ObjectsClassDeleteInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this objects class delete internal server error response has a 5xx status code
func (o *ObjectsClassDeleteInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this objects class delete internal server error response a status code equal to that given
func (o *ObjectsClassDeleteInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the objects class delete internal server error response
func (o *ObjectsClassDeleteInternalServerError) Code() int {
	return 500
}

func (o *ObjectsClassDeleteInternalServerError) Error() string {
	return fmt.Sprintf("[DELETE /objects/{className}/{id}][%d] objectsClassDeleteInternalServerError  %+v", 500, o.Payload)
}

func (o *ObjectsClassDeleteInternalServerError) String() string {
	return fmt.Sprintf("[DELETE /objects/{className}/{id}][%d] objectsClassDeleteInternalServerError  %+v", 500, o.Payload)
}

func (o *ObjectsClassDeleteInternalServerError) GetPayload() *models.ErrorResponse {
	return o.Payload
}

func (o *ObjectsClassDeleteInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
