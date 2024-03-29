// Code generated by go-swagger; DO NOT EDIT.

package domain_management

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"

	models "github.com/Prashanth-GS/test-swagger/models"
)

// NewPostToplevelDomainParams creates a new PostToplevelDomainParams object
// no default values defined in spec.
func NewPostToplevelDomainParams() PostToplevelDomainParams {

	return PostToplevelDomainParams{}
}

// PostToplevelDomainParams contains all the bound params for the post toplevel domain operation
// typically these are obtained from a http.Request
//
// swagger:parameters PostToplevelDomain
type PostToplevelDomainParams struct {

	// HTTP Request Object
	HTTPRequest *http.Request `json:"-"`

	/*
	  In: body
	*/
	AddTLDRequest *models.ToplevelDomain
}

// BindRequest both binds and validates a request, it assumes that complex things implement a Validatable(strfmt.Registry) error interface
// for simple values it will use straight method calls.
//
// To ensure default values, the struct must have been initialized with NewPostToplevelDomainParams() beforehand.
func (o *PostToplevelDomainParams) BindRequest(r *http.Request, route *middleware.MatchedRoute) error {
	var res []error

	o.HTTPRequest = r

	if runtime.HasBody(r) {
		defer r.Body.Close()
		var body models.ToplevelDomain
		if err := route.Consumer.Consume(r.Body, &body); err != nil {
			res = append(res, errors.NewParseError("addTLDRequest", "body", "", err))
		} else {
			// validate body object
			if err := body.Validate(route.Formats); err != nil {
				res = append(res, err)
			}

			if len(res) == 0 {
				o.AddTLDRequest = &body
			}
		}
	}
	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
