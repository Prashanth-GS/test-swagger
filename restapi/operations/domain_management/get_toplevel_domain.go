// Code generated by go-swagger; DO NOT EDIT.

package domain_management

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"

	middleware "github.com/go-openapi/runtime/middleware"
)

// GetToplevelDomainHandlerFunc turns a function with the right signature into a get toplevel domain handler
type GetToplevelDomainHandlerFunc func(GetToplevelDomainParams) middleware.Responder

// Handle executing the request and returning a response
func (fn GetToplevelDomainHandlerFunc) Handle(params GetToplevelDomainParams) middleware.Responder {
	return fn(params)
}

// GetToplevelDomainHandler interface for that can handle valid get toplevel domain params
type GetToplevelDomainHandler interface {
	Handle(GetToplevelDomainParams) middleware.Responder
}

// NewGetToplevelDomain creates a new http.Handler for the get toplevel domain operation
func NewGetToplevelDomain(ctx *middleware.Context, handler GetToplevelDomainHandler) *GetToplevelDomain {
	return &GetToplevelDomain{Context: ctx, Handler: handler}
}

/*GetToplevelDomain swagger:route GET /toplevel-domain domain-management getToplevelDomain

GetToplevelDomain get toplevel domain API

*/
type GetToplevelDomain struct {
	Context *middleware.Context
	Handler GetToplevelDomainHandler
}

func (o *GetToplevelDomain) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		r = rCtx
	}
	var Params = NewGetToplevelDomainParams()

	if err := o.Context.BindValidRequest(r, route, &Params); err != nil { // bind params
		o.Context.Respond(rw, r, route.Produces, route, err)
		return
	}

	res := o.Handler.Handle(Params) // actually handle the request

	o.Context.Respond(rw, r, route.Produces, route, res)

}
