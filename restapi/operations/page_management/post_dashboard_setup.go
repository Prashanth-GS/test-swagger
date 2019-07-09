// Code generated by go-swagger; DO NOT EDIT.

package page_management

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"

	middleware "github.com/go-openapi/runtime/middleware"
)

// PostDashboardSetupHandlerFunc turns a function with the right signature into a post dashboard setup handler
type PostDashboardSetupHandlerFunc func(PostDashboardSetupParams) middleware.Responder

// Handle executing the request and returning a response
func (fn PostDashboardSetupHandlerFunc) Handle(params PostDashboardSetupParams) middleware.Responder {
	return fn(params)
}

// PostDashboardSetupHandler interface for that can handle valid post dashboard setup params
type PostDashboardSetupHandler interface {
	Handle(PostDashboardSetupParams) middleware.Responder
}

// NewPostDashboardSetup creates a new http.Handler for the post dashboard setup operation
func NewPostDashboardSetup(ctx *middleware.Context, handler PostDashboardSetupHandler) *PostDashboardSetup {
	return &PostDashboardSetup{Context: ctx, Handler: handler}
}

/*PostDashboardSetup swagger:route POST /dashboard-setup page-management postDashboardSetup

PostDashboardSetup post dashboard setup API

*/
type PostDashboardSetup struct {
	Context *middleware.Context
	Handler PostDashboardSetupHandler
}

func (o *PostDashboardSetup) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		r = rCtx
	}
	var Params = NewPostDashboardSetupParams()

	if err := o.Context.BindValidRequest(r, route, &Params); err != nil { // bind params
		o.Context.Respond(rw, r, route.Produces, route, err)
		return
	}

	res := o.Handler.Handle(Params) // actually handle the request

	o.Context.Respond(rw, r, route.Produces, route, res)

}