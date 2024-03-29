// Code generated by go-swagger; DO NOT EDIT.

package domain_management

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	models "github.com/Prashanth-GS/test-swagger/models"
)

// GetToplevelDomainOKCode is the HTTP code returned for type GetToplevelDomainOK
const GetToplevelDomainOKCode int = 200

/*GetToplevelDomainOK OK

swagger:response getToplevelDomainOK
*/
type GetToplevelDomainOK struct {

	/*
	  In: Body
	*/
	Payload *models.AllTLDResponse `json:"body,omitempty"`
}

// NewGetToplevelDomainOK creates GetToplevelDomainOK with default headers values
func NewGetToplevelDomainOK() *GetToplevelDomainOK {

	return &GetToplevelDomainOK{}
}

// WithPayload adds the payload to the get toplevel domain o k response
func (o *GetToplevelDomainOK) WithPayload(payload *models.AllTLDResponse) *GetToplevelDomainOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the get toplevel domain o k response
func (o *GetToplevelDomainOK) SetPayload(payload *models.AllTLDResponse) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *GetToplevelDomainOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// GetToplevelDomainBadRequestCode is the HTTP code returned for type GetToplevelDomainBadRequest
const GetToplevelDomainBadRequestCode int = 400

/*GetToplevelDomainBadRequest BAD REQUEST

swagger:response getToplevelDomainBadRequest
*/
type GetToplevelDomainBadRequest struct {

	/*
	  In: Body
	*/
	Payload *models.GeneralResponse `json:"body,omitempty"`
}

// NewGetToplevelDomainBadRequest creates GetToplevelDomainBadRequest with default headers values
func NewGetToplevelDomainBadRequest() *GetToplevelDomainBadRequest {

	return &GetToplevelDomainBadRequest{}
}

// WithPayload adds the payload to the get toplevel domain bad request response
func (o *GetToplevelDomainBadRequest) WithPayload(payload *models.GeneralResponse) *GetToplevelDomainBadRequest {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the get toplevel domain bad request response
func (o *GetToplevelDomainBadRequest) SetPayload(payload *models.GeneralResponse) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *GetToplevelDomainBadRequest) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(400)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// GetToplevelDomainUnauthorizedCode is the HTTP code returned for type GetToplevelDomainUnauthorized
const GetToplevelDomainUnauthorizedCode int = 401

/*GetToplevelDomainUnauthorized UNAUTHORIZED

swagger:response getToplevelDomainUnauthorized
*/
type GetToplevelDomainUnauthorized struct {

	/*
	  In: Body
	*/
	Payload *models.GeneralResponse `json:"body,omitempty"`
}

// NewGetToplevelDomainUnauthorized creates GetToplevelDomainUnauthorized with default headers values
func NewGetToplevelDomainUnauthorized() *GetToplevelDomainUnauthorized {

	return &GetToplevelDomainUnauthorized{}
}

// WithPayload adds the payload to the get toplevel domain unauthorized response
func (o *GetToplevelDomainUnauthorized) WithPayload(payload *models.GeneralResponse) *GetToplevelDomainUnauthorized {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the get toplevel domain unauthorized response
func (o *GetToplevelDomainUnauthorized) SetPayload(payload *models.GeneralResponse) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *GetToplevelDomainUnauthorized) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(401)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// GetToplevelDomainForbiddenCode is the HTTP code returned for type GetToplevelDomainForbidden
const GetToplevelDomainForbiddenCode int = 403

/*GetToplevelDomainForbidden FORBIDDEN

swagger:response getToplevelDomainForbidden
*/
type GetToplevelDomainForbidden struct {

	/*
	  In: Body
	*/
	Payload *models.GeneralResponse `json:"body,omitempty"`
}

// NewGetToplevelDomainForbidden creates GetToplevelDomainForbidden with default headers values
func NewGetToplevelDomainForbidden() *GetToplevelDomainForbidden {

	return &GetToplevelDomainForbidden{}
}

// WithPayload adds the payload to the get toplevel domain forbidden response
func (o *GetToplevelDomainForbidden) WithPayload(payload *models.GeneralResponse) *GetToplevelDomainForbidden {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the get toplevel domain forbidden response
func (o *GetToplevelDomainForbidden) SetPayload(payload *models.GeneralResponse) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *GetToplevelDomainForbidden) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(403)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// GetToplevelDomainNotFoundCode is the HTTP code returned for type GetToplevelDomainNotFound
const GetToplevelDomainNotFoundCode int = 404

/*GetToplevelDomainNotFound NOT FOUND

swagger:response getToplevelDomainNotFound
*/
type GetToplevelDomainNotFound struct {

	/*
	  In: Body
	*/
	Payload *models.GeneralResponse `json:"body,omitempty"`
}

// NewGetToplevelDomainNotFound creates GetToplevelDomainNotFound with default headers values
func NewGetToplevelDomainNotFound() *GetToplevelDomainNotFound {

	return &GetToplevelDomainNotFound{}
}

// WithPayload adds the payload to the get toplevel domain not found response
func (o *GetToplevelDomainNotFound) WithPayload(payload *models.GeneralResponse) *GetToplevelDomainNotFound {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the get toplevel domain not found response
func (o *GetToplevelDomainNotFound) SetPayload(payload *models.GeneralResponse) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *GetToplevelDomainNotFound) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(404)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// GetToplevelDomainInternalServerErrorCode is the HTTP code returned for type GetToplevelDomainInternalServerError
const GetToplevelDomainInternalServerErrorCode int = 500

/*GetToplevelDomainInternalServerError INTERNAL SERVER ERROR

swagger:response getToplevelDomainInternalServerError
*/
type GetToplevelDomainInternalServerError struct {

	/*
	  In: Body
	*/
	Payload *models.GeneralResponse `json:"body,omitempty"`
}

// NewGetToplevelDomainInternalServerError creates GetToplevelDomainInternalServerError with default headers values
func NewGetToplevelDomainInternalServerError() *GetToplevelDomainInternalServerError {

	return &GetToplevelDomainInternalServerError{}
}

// WithPayload adds the payload to the get toplevel domain internal server error response
func (o *GetToplevelDomainInternalServerError) WithPayload(payload *models.GeneralResponse) *GetToplevelDomainInternalServerError {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the get toplevel domain internal server error response
func (o *GetToplevelDomainInternalServerError) SetPayload(payload *models.GeneralResponse) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *GetToplevelDomainInternalServerError) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(500)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}
