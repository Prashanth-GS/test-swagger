// Code generated by go-swagger; DO NOT EDIT.

package page_management

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"

	middleware "github.com/go-openapi/runtime/middleware"
)

// GetDashboardDetailsEmailTypeHandlerFunc turns a function with the right signature into a get dashboard details email type handler
type GetDashboardDetailsEmailTypeHandlerFunc func(GetDashboardDetailsEmailTypeParams) middleware.Responder

// Handle executing the request and returning a response
func (fn GetDashboardDetailsEmailTypeHandlerFunc) Handle(params GetDashboardDetailsEmailTypeParams) middleware.Responder {
	return fn(params)
}

// GetDashboardDetailsEmailTypeHandler interface for that can handle valid get dashboard details email type params
type GetDashboardDetailsEmailTypeHandler interface {
	Handle(GetDashboardDetailsEmailTypeParams) middleware.Responder
}

// NewGetDashboardDetailsEmailType creates a new http.Handler for the get dashboard details email type operation
func NewGetDashboardDetailsEmailType(ctx *middleware.Context, handler GetDashboardDetailsEmailTypeHandler) *GetDashboardDetailsEmailType {
	return &GetDashboardDetailsEmailType{Context: ctx, Handler: handler}
}

/*GetDashboardDetailsEmailType swagger:route GET /dashboard-details/{email}/{type} page-management getDashboardDetailsEmailType

GetDashboardDetailsEmailType get dashboard details email type API

*/
type GetDashboardDetailsEmailType struct {
	Context *middleware.Context
	Handler GetDashboardDetailsEmailTypeHandler
}

func (o *GetDashboardDetailsEmailType) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		r = rCtx
	}
	var Params = NewGetDashboardDetailsEmailTypeParams()

	if err := o.Context.BindValidRequest(r, route, &Params); err != nil { // bind params
		o.Context.Respond(rw, r, route.Produces, route, err)
		return
	}

	res := o.Handler.Handle(Params) // actually handle the request

	o.Context.Respond(rw, r, route.Produces, route, res)

}
