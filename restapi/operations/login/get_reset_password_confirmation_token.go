// Code generated by go-swagger; DO NOT EDIT.

package login

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"

	middleware "github.com/go-openapi/runtime/middleware"
)

// GetResetPasswordConfirmationTokenHandlerFunc turns a function with the right signature into a get reset password confirmation token handler
type GetResetPasswordConfirmationTokenHandlerFunc func(GetResetPasswordConfirmationTokenParams) middleware.Responder

// Handle executing the request and returning a response
func (fn GetResetPasswordConfirmationTokenHandlerFunc) Handle(params GetResetPasswordConfirmationTokenParams) middleware.Responder {
	return fn(params)
}

// GetResetPasswordConfirmationTokenHandler interface for that can handle valid get reset password confirmation token params
type GetResetPasswordConfirmationTokenHandler interface {
	Handle(GetResetPasswordConfirmationTokenParams) middleware.Responder
}

// NewGetResetPasswordConfirmationToken creates a new http.Handler for the get reset password confirmation token operation
func NewGetResetPasswordConfirmationToken(ctx *middleware.Context, handler GetResetPasswordConfirmationTokenHandler) *GetResetPasswordConfirmationToken {
	return &GetResetPasswordConfirmationToken{Context: ctx, Handler: handler}
}

/*GetResetPasswordConfirmationToken swagger:route GET /reset-password-confirmation/{token} login getResetPasswordConfirmationToken

GetResetPasswordConfirmationToken get reset password confirmation token API

*/
type GetResetPasswordConfirmationToken struct {
	Context *middleware.Context
	Handler GetResetPasswordConfirmationTokenHandler
}

func (o *GetResetPasswordConfirmationToken) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		r = rCtx
	}
	var Params = NewGetResetPasswordConfirmationTokenParams()

	if err := o.Context.BindValidRequest(r, route, &Params); err != nil { // bind params
		o.Context.Respond(rw, r, route.Produces, route, err)
		return
	}

	res := o.Handler.Handle(Params) // actually handle the request

	o.Context.Respond(rw, r, route.Produces, route, res)

}
