// Code generated by go-swagger; DO NOT EDIT.

package users_management

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	models "github.com/Prashanth-GS/test-swagger/models"
)

// PostLockUserOKCode is the HTTP code returned for type PostLockUserOK
const PostLockUserOKCode int = 200

/*PostLockUserOK OK

swagger:response postLockUserOK
*/
type PostLockUserOK struct {

	/*
	  In: Body
	*/
	Payload *models.GeneralResponse `json:"body,omitempty"`
}

// NewPostLockUserOK creates PostLockUserOK with default headers values
func NewPostLockUserOK() *PostLockUserOK {

	return &PostLockUserOK{}
}

// WithPayload adds the payload to the post lock user o k response
func (o *PostLockUserOK) WithPayload(payload *models.GeneralResponse) *PostLockUserOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the post lock user o k response
func (o *PostLockUserOK) SetPayload(payload *models.GeneralResponse) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *PostLockUserOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// PostLockUserBadRequestCode is the HTTP code returned for type PostLockUserBadRequest
const PostLockUserBadRequestCode int = 400

/*PostLockUserBadRequest BAD REQUEST

swagger:response postLockUserBadRequest
*/
type PostLockUserBadRequest struct {

	/*
	  In: Body
	*/
	Payload *models.GeneralResponse `json:"body,omitempty"`
}

// NewPostLockUserBadRequest creates PostLockUserBadRequest with default headers values
func NewPostLockUserBadRequest() *PostLockUserBadRequest {

	return &PostLockUserBadRequest{}
}

// WithPayload adds the payload to the post lock user bad request response
func (o *PostLockUserBadRequest) WithPayload(payload *models.GeneralResponse) *PostLockUserBadRequest {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the post lock user bad request response
func (o *PostLockUserBadRequest) SetPayload(payload *models.GeneralResponse) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *PostLockUserBadRequest) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(400)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// PostLockUserUnauthorizedCode is the HTTP code returned for type PostLockUserUnauthorized
const PostLockUserUnauthorizedCode int = 401

/*PostLockUserUnauthorized UNAUTHORIZED

swagger:response postLockUserUnauthorized
*/
type PostLockUserUnauthorized struct {

	/*
	  In: Body
	*/
	Payload *models.GeneralResponse `json:"body,omitempty"`
}

// NewPostLockUserUnauthorized creates PostLockUserUnauthorized with default headers values
func NewPostLockUserUnauthorized() *PostLockUserUnauthorized {

	return &PostLockUserUnauthorized{}
}

// WithPayload adds the payload to the post lock user unauthorized response
func (o *PostLockUserUnauthorized) WithPayload(payload *models.GeneralResponse) *PostLockUserUnauthorized {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the post lock user unauthorized response
func (o *PostLockUserUnauthorized) SetPayload(payload *models.GeneralResponse) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *PostLockUserUnauthorized) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(401)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// PostLockUserForbiddenCode is the HTTP code returned for type PostLockUserForbidden
const PostLockUserForbiddenCode int = 403

/*PostLockUserForbidden FORBIDDEN

swagger:response postLockUserForbidden
*/
type PostLockUserForbidden struct {

	/*
	  In: Body
	*/
	Payload *models.GeneralResponse `json:"body,omitempty"`
}

// NewPostLockUserForbidden creates PostLockUserForbidden with default headers values
func NewPostLockUserForbidden() *PostLockUserForbidden {

	return &PostLockUserForbidden{}
}

// WithPayload adds the payload to the post lock user forbidden response
func (o *PostLockUserForbidden) WithPayload(payload *models.GeneralResponse) *PostLockUserForbidden {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the post lock user forbidden response
func (o *PostLockUserForbidden) SetPayload(payload *models.GeneralResponse) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *PostLockUserForbidden) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(403)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// PostLockUserNotFoundCode is the HTTP code returned for type PostLockUserNotFound
const PostLockUserNotFoundCode int = 404

/*PostLockUserNotFound NOT FOUND

swagger:response postLockUserNotFound
*/
type PostLockUserNotFound struct {

	/*
	  In: Body
	*/
	Payload *models.GeneralResponse `json:"body,omitempty"`
}

// NewPostLockUserNotFound creates PostLockUserNotFound with default headers values
func NewPostLockUserNotFound() *PostLockUserNotFound {

	return &PostLockUserNotFound{}
}

// WithPayload adds the payload to the post lock user not found response
func (o *PostLockUserNotFound) WithPayload(payload *models.GeneralResponse) *PostLockUserNotFound {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the post lock user not found response
func (o *PostLockUserNotFound) SetPayload(payload *models.GeneralResponse) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *PostLockUserNotFound) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(404)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// PostLockUserInternalServerErrorCode is the HTTP code returned for type PostLockUserInternalServerError
const PostLockUserInternalServerErrorCode int = 500

/*PostLockUserInternalServerError INTERNAL SERVER ERROR

swagger:response postLockUserInternalServerError
*/
type PostLockUserInternalServerError struct {

	/*
	  In: Body
	*/
	Payload *models.GeneralResponse `json:"body,omitempty"`
}

// NewPostLockUserInternalServerError creates PostLockUserInternalServerError with default headers values
func NewPostLockUserInternalServerError() *PostLockUserInternalServerError {

	return &PostLockUserInternalServerError{}
}

// WithPayload adds the payload to the post lock user internal server error response
func (o *PostLockUserInternalServerError) WithPayload(payload *models.GeneralResponse) *PostLockUserInternalServerError {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the post lock user internal server error response
func (o *PostLockUserInternalServerError) SetPayload(payload *models.GeneralResponse) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *PostLockUserInternalServerError) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(500)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}