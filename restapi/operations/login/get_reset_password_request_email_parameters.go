// Code generated by go-swagger; DO NOT EDIT.

package login

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime/middleware"

	strfmt "github.com/go-openapi/strfmt"
)

// NewGetResetPasswordRequestEmailParams creates a new GetResetPasswordRequestEmailParams object
// no default values defined in spec.
func NewGetResetPasswordRequestEmailParams() GetResetPasswordRequestEmailParams {

	return GetResetPasswordRequestEmailParams{}
}

// GetResetPasswordRequestEmailParams contains all the bound params for the get reset password request email operation
// typically these are obtained from a http.Request
//
// swagger:parameters GetResetPasswordRequestEmail
type GetResetPasswordRequestEmailParams struct {

	// HTTP Request Object
	HTTPRequest *http.Request `json:"-"`

	/*
	  Required: true
	  In: path
	*/
	Email string
}

// BindRequest both binds and validates a request, it assumes that complex things implement a Validatable(strfmt.Registry) error interface
// for simple values it will use straight method calls.
//
// To ensure default values, the struct must have been initialized with NewGetResetPasswordRequestEmailParams() beforehand.
func (o *GetResetPasswordRequestEmailParams) BindRequest(r *http.Request, route *middleware.MatchedRoute) error {
	var res []error

	o.HTTPRequest = r

	rEmail, rhkEmail, _ := route.Params.GetOK("email")
	if err := o.bindEmail(rEmail, rhkEmail, route.Formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// bindEmail binds and validates parameter Email from path.
func (o *GetResetPasswordRequestEmailParams) bindEmail(rawData []string, hasKey bool, formats strfmt.Registry) error {
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: true
	// Parameter is provided by construction from the route

	o.Email = raw

	return nil
}