// Code generated by go-swagger; DO NOT EDIT.

package news

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"

	middleware "github.com/go-openapi/runtime/middleware"
)

// GetNewsHandlerFunc turns a function with the right signature into a get news handler
type GetNewsHandlerFunc func(GetNewsParams) middleware.Responder

// Handle executing the request and returning a response
func (fn GetNewsHandlerFunc) Handle(params GetNewsParams) middleware.Responder {
	return fn(params)
}

// GetNewsHandler interface for that can handle valid get news params
type GetNewsHandler interface {
	Handle(GetNewsParams) middleware.Responder
}

// NewGetNews creates a new http.Handler for the get news operation
func NewGetNews(ctx *middleware.Context, handler GetNewsHandler) *GetNews {
	return &GetNews{Context: ctx, Handler: handler}
}

/*GetNews swagger:route GET /news news getNews

GetNews get news API

*/
type GetNews struct {
	Context *middleware.Context
	Handler GetNewsHandler
}

func (o *GetNews) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		r = rCtx
	}
	var Params = NewGetNewsParams()

	if err := o.Context.BindValidRequest(r, route, &Params); err != nil { // bind params
		o.Context.Respond(rw, r, route.Produces, route, err)
		return
	}

	res := o.Handler.Handle(Params) // actually handle the request

	o.Context.Respond(rw, r, route.Produces, route, res)

}
