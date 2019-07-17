// Code generated by go-swagger; DO NOT EDIT.

package domain_management

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"

	middleware "github.com/go-openapi/runtime/middleware"
)

// PostToplevelDomainHandlerFunc turns a function with the right signature into a post toplevel domain handler
type PostToplevelDomainHandlerFunc func(PostToplevelDomainParams) middleware.Responder

// Handle executing the request and returning a response
func (fn PostToplevelDomainHandlerFunc) Handle(params PostToplevelDomainParams) middleware.Responder {
	return fn(params)
}

// PostToplevelDomainHandler interface for that can handle valid post toplevel domain params
type PostToplevelDomainHandler interface {
	Handle(PostToplevelDomainParams) middleware.Responder
}

// NewPostToplevelDomain creates a new http.Handler for the post toplevel domain operation
func NewPostToplevelDomain(ctx *middleware.Context, handler PostToplevelDomainHandler) *PostToplevelDomain {
	return &PostToplevelDomain{Context: ctx, Handler: handler}
}

/*PostToplevelDomain swagger:route POST /toplevel-domain domain-management postToplevelDomain

PostToplevelDomain post toplevel domain API

*/
type PostToplevelDomain struct {
	Context *middleware.Context
	Handler PostToplevelDomainHandler
}

func (o *PostToplevelDomain) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		r = rCtx
	}
	var Params = NewPostToplevelDomainParams()

	if err := o.Context.BindValidRequest(r, route, &Params); err != nil { // bind params
		o.Context.Respond(rw, r, route.Produces, route, err)
		return
	}

	res := o.Handler.Handle(Params) // actually handle the request

	o.Context.Respond(rw, r, route.Produces, route, res)

}