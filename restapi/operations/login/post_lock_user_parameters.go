// Code generated by go-swagger; DO NOT EDIT.

package login

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"

	models "github.com/Prashanth-GS/test-swagger/models"
)

// NewPostLockUserParams creates a new PostLockUserParams object
// no default values defined in spec.
func NewPostLockUserParams() PostLockUserParams {

	return PostLockUserParams{}
}

// PostLockUserParams contains all the bound params for the post lock user operation
// typically these are obtained from a http.Request
//
// swagger:parameters PostLockUser
type PostLockUserParams struct {

	// HTTP Request Object
	HTTPRequest *http.Request `json:"-"`

	/*
	  In: body
	*/
	LockUserRequest *models.LockUserRequest
}

// BindRequest both binds and validates a request, it assumes that complex things implement a Validatable(strfmt.Registry) error interface
// for simple values it will use straight method calls.
//
// To ensure default values, the struct must have been initialized with NewPostLockUserParams() beforehand.
func (o *PostLockUserParams) BindRequest(r *http.Request, route *middleware.MatchedRoute) error {
	var res []error

	o.HTTPRequest = r

	if runtime.HasBody(r) {
		defer r.Body.Close()
		var body models.LockUserRequest
		if err := route.Consumer.Consume(r.Body, &body); err != nil {
			res = append(res, errors.NewParseError("lockUserRequest", "body", "", err))
		} else {
			// validate body object
			if err := body.Validate(route.Formats); err != nil {
				res = append(res, err)
			}

			if len(res) == 0 {
				o.LockUserRequest = &body
			}
		}
	}
	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
