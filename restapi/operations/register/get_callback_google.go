// Code generated by go-swagger; DO NOT EDIT.

package register

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"

	middleware "github.com/go-openapi/runtime/middleware"
)

// GetCallbackGoogleHandlerFunc turns a function with the right signature into a get callback google handler
type GetCallbackGoogleHandlerFunc func(GetCallbackGoogleParams) middleware.Responder

// Handle executing the request and returning a response
func (fn GetCallbackGoogleHandlerFunc) Handle(params GetCallbackGoogleParams) middleware.Responder {
	return fn(params)
}

// GetCallbackGoogleHandler interface for that can handle valid get callback google params
type GetCallbackGoogleHandler interface {
	Handle(GetCallbackGoogleParams) middleware.Responder
}

// NewGetCallbackGoogle creates a new http.Handler for the get callback google operation
func NewGetCallbackGoogle(ctx *middleware.Context, handler GetCallbackGoogleHandler) *GetCallbackGoogle {
	return &GetCallbackGoogle{Context: ctx, Handler: handler}
}

/*GetCallbackGoogle swagger:route GET /callback-google register getCallbackGoogle

GetCallbackGoogle get callback google API

*/
type GetCallbackGoogle struct {
	Context *middleware.Context
	Handler GetCallbackGoogleHandler
}

func (o *GetCallbackGoogle) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		r = rCtx
	}
	var Params = NewGetCallbackGoogleParams()

	if err := o.Context.BindValidRequest(r, route, &Params); err != nil { // bind params
		o.Context.Respond(rw, r, route.Produces, route, err)
		return
	}

	res := o.Handler.Handle(Params) // actually handle the request

	o.Context.Respond(rw, r, route.Produces, route, res)

}
