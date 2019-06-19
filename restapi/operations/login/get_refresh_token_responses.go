// Code generated by go-swagger; DO NOT EDIT.

package login

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	models "github.com/Prashanth-GS/test-swagger/models"
)

// GetRefreshTokenOKCode is the HTTP code returned for type GetRefreshTokenOK
const GetRefreshTokenOKCode int = 200

/*GetRefreshTokenOK OK

swagger:response getRefreshTokenOK
*/
type GetRefreshTokenOK struct {

	/*
	  In: Body
	*/
	Payload *models.LoginResponse `json:"body,omitempty"`
}

// NewGetRefreshTokenOK creates GetRefreshTokenOK with default headers values
func NewGetRefreshTokenOK() *GetRefreshTokenOK {

	return &GetRefreshTokenOK{}
}

// WithPayload adds the payload to the get refresh token o k response
func (o *GetRefreshTokenOK) WithPayload(payload *models.LoginResponse) *GetRefreshTokenOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the get refresh token o k response
func (o *GetRefreshTokenOK) SetPayload(payload *models.LoginResponse) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *GetRefreshTokenOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// GetRefreshTokenBadRequestCode is the HTTP code returned for type GetRefreshTokenBadRequest
const GetRefreshTokenBadRequestCode int = 400

/*GetRefreshTokenBadRequest BAD REQUEST

swagger:response getRefreshTokenBadRequest
*/
type GetRefreshTokenBadRequest struct {

	/*
	  In: Body
	*/
	Payload *models.GeneralResponse `json:"body,omitempty"`
}

// NewGetRefreshTokenBadRequest creates GetRefreshTokenBadRequest with default headers values
func NewGetRefreshTokenBadRequest() *GetRefreshTokenBadRequest {

	return &GetRefreshTokenBadRequest{}
}

// WithPayload adds the payload to the get refresh token bad request response
func (o *GetRefreshTokenBadRequest) WithPayload(payload *models.GeneralResponse) *GetRefreshTokenBadRequest {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the get refresh token bad request response
func (o *GetRefreshTokenBadRequest) SetPayload(payload *models.GeneralResponse) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *GetRefreshTokenBadRequest) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(400)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// GetRefreshTokenUnauthorizedCode is the HTTP code returned for type GetRefreshTokenUnauthorized
const GetRefreshTokenUnauthorizedCode int = 401

/*GetRefreshTokenUnauthorized UNAUTHORIZED

swagger:response getRefreshTokenUnauthorized
*/
type GetRefreshTokenUnauthorized struct {

	/*
	  In: Body
	*/
	Payload *models.GeneralResponse `json:"body,omitempty"`
}

// NewGetRefreshTokenUnauthorized creates GetRefreshTokenUnauthorized with default headers values
func NewGetRefreshTokenUnauthorized() *GetRefreshTokenUnauthorized {

	return &GetRefreshTokenUnauthorized{}
}

// WithPayload adds the payload to the get refresh token unauthorized response
func (o *GetRefreshTokenUnauthorized) WithPayload(payload *models.GeneralResponse) *GetRefreshTokenUnauthorized {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the get refresh token unauthorized response
func (o *GetRefreshTokenUnauthorized) SetPayload(payload *models.GeneralResponse) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *GetRefreshTokenUnauthorized) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(401)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// GetRefreshTokenForbiddenCode is the HTTP code returned for type GetRefreshTokenForbidden
const GetRefreshTokenForbiddenCode int = 403

/*GetRefreshTokenForbidden FORBIDDEN

swagger:response getRefreshTokenForbidden
*/
type GetRefreshTokenForbidden struct {

	/*
	  In: Body
	*/
	Payload *models.GeneralResponse `json:"body,omitempty"`
}

// NewGetRefreshTokenForbidden creates GetRefreshTokenForbidden with default headers values
func NewGetRefreshTokenForbidden() *GetRefreshTokenForbidden {

	return &GetRefreshTokenForbidden{}
}

// WithPayload adds the payload to the get refresh token forbidden response
func (o *GetRefreshTokenForbidden) WithPayload(payload *models.GeneralResponse) *GetRefreshTokenForbidden {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the get refresh token forbidden response
func (o *GetRefreshTokenForbidden) SetPayload(payload *models.GeneralResponse) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *GetRefreshTokenForbidden) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(403)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// GetRefreshTokenNotFoundCode is the HTTP code returned for type GetRefreshTokenNotFound
const GetRefreshTokenNotFoundCode int = 404

/*GetRefreshTokenNotFound NOT FOUND

swagger:response getRefreshTokenNotFound
*/
type GetRefreshTokenNotFound struct {

	/*
	  In: Body
	*/
	Payload *models.GeneralResponse `json:"body,omitempty"`
}

// NewGetRefreshTokenNotFound creates GetRefreshTokenNotFound with default headers values
func NewGetRefreshTokenNotFound() *GetRefreshTokenNotFound {

	return &GetRefreshTokenNotFound{}
}

// WithPayload adds the payload to the get refresh token not found response
func (o *GetRefreshTokenNotFound) WithPayload(payload *models.GeneralResponse) *GetRefreshTokenNotFound {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the get refresh token not found response
func (o *GetRefreshTokenNotFound) SetPayload(payload *models.GeneralResponse) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *GetRefreshTokenNotFound) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(404)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// GetRefreshTokenInternalServerErrorCode is the HTTP code returned for type GetRefreshTokenInternalServerError
const GetRefreshTokenInternalServerErrorCode int = 500

/*GetRefreshTokenInternalServerError INTERNAL SERVER ERROR

swagger:response getRefreshTokenInternalServerError
*/
type GetRefreshTokenInternalServerError struct {

	/*
	  In: Body
	*/
	Payload *models.GeneralResponse `json:"body,omitempty"`
}

// NewGetRefreshTokenInternalServerError creates GetRefreshTokenInternalServerError with default headers values
func NewGetRefreshTokenInternalServerError() *GetRefreshTokenInternalServerError {

	return &GetRefreshTokenInternalServerError{}
}

// WithPayload adds the payload to the get refresh token internal server error response
func (o *GetRefreshTokenInternalServerError) WithPayload(payload *models.GeneralResponse) *GetRefreshTokenInternalServerError {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the get refresh token internal server error response
func (o *GetRefreshTokenInternalServerError) SetPayload(payload *models.GeneralResponse) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *GetRefreshTokenInternalServerError) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(500)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}