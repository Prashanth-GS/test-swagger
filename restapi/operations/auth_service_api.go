// Code generated by go-swagger; DO NOT EDIT.

package operations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"net/http"
	"strings"

	errors "github.com/go-openapi/errors"
	loads "github.com/go-openapi/loads"
	runtime "github.com/go-openapi/runtime"
	middleware "github.com/go-openapi/runtime/middleware"
	security "github.com/go-openapi/runtime/security"
	spec "github.com/go-openapi/spec"
	strfmt "github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"

	"github.com/Prashanth-GS/test-swagger/restapi/operations/login"
	"github.com/Prashanth-GS/test-swagger/restapi/operations/register"
)

// NewAuthServiceAPI creates a new AuthService instance
func NewAuthServiceAPI(spec *loads.Document) *AuthServiceAPI {
	return &AuthServiceAPI{
		handlers:            make(map[string]map[string]http.Handler),
		formats:             strfmt.Default,
		defaultConsumes:     "application/json",
		defaultProduces:     "application/json",
		customConsumers:     make(map[string]runtime.Consumer),
		customProducers:     make(map[string]runtime.Producer),
		ServerShutdown:      func() {},
		spec:                spec,
		ServeError:          errors.ServeError,
		BasicAuthenticator:  security.BasicAuth,
		APIKeyAuthenticator: security.APIKeyAuth,
		BearerAuthenticator: security.BearerAuth,
		JSONConsumer:        runtime.JSONConsumer(),
		JSONProducer:        runtime.JSONProducer(),
		RegisterGetRegisterConfirmationTokenHandler:   nil,
		LoginGetResetPasswordConfirmationTokenHandler: nil,
		LoginGetResetPasswordRequestEmailHandler:      nil,
		LoginPostLoginHandler:                         nil,
		RegisterPostRegisterHandler:                   nil,
		RegisterPostRegisterDetailsHandler:            nil,
		LoginPostResetPasswordHandler:                 nil,
		RegisterGetCallbackGoogleHandler:              nil,
	}
}

/*AuthServiceAPI Authentication Service API */
type AuthServiceAPI struct {
	spec            *loads.Document
	context         *middleware.Context
	handlers        map[string]map[string]http.Handler
	formats         strfmt.Registry
	customConsumers map[string]runtime.Consumer
	customProducers map[string]runtime.Producer
	defaultConsumes string
	defaultProduces string
	Middleware      func(middleware.Builder) http.Handler

	// BasicAuthenticator generates a runtime.Authenticator from the supplied basic auth function.
	// It has a default implementation in the security package, however you can replace it for your particular usage.
	BasicAuthenticator func(security.UserPassAuthentication) runtime.Authenticator
	// APIKeyAuthenticator generates a runtime.Authenticator from the supplied token auth function.
	// It has a default implementation in the security package, however you can replace it for your particular usage.
	APIKeyAuthenticator func(string, string, security.TokenAuthentication) runtime.Authenticator
	// BearerAuthenticator generates a runtime.Authenticator from the supplied bearer token auth function.
	// It has a default implementation in the security package, however you can replace it for your particular usage.
	BearerAuthenticator func(string, security.ScopedTokenAuthentication) runtime.Authenticator

	// JSONConsumer registers a consumer for a "application/json" mime type
	JSONConsumer runtime.Consumer

	// JSONProducer registers a producer for a "application/json" mime type
	JSONProducer runtime.Producer

	// RegisterGetCallbackGoogleHandler sets the operation handler for the get callback google operation
	RegisterGetCallbackGoogleHandler register.GetCallbackGoogleHandler
	// RegisterGetRegisterConfirmationTokenHandler sets the operation handler for the get register confirmation token operation
	RegisterGetRegisterConfirmationTokenHandler register.GetRegisterConfirmationTokenHandler
	// LoginGetResetPasswordConfirmationTokenHandler sets the operation handler for the get reset password confirmation token operation
	LoginGetResetPasswordConfirmationTokenHandler login.GetResetPasswordConfirmationTokenHandler
	// LoginGetResetPasswordRequestEmailHandler sets the operation handler for the get reset password request email operation
	LoginGetResetPasswordRequestEmailHandler login.GetResetPasswordRequestEmailHandler
	// LoginPostLoginHandler sets the operation handler for the post login operation
	LoginPostLoginHandler login.PostLoginHandler
	// RegisterPostRegisterHandler sets the operation handler for the post register operation
	RegisterPostRegisterHandler register.PostRegisterHandler
	// RegisterPostRegisterDetailsHandler sets the operation handler for the post register details operation
	RegisterPostRegisterDetailsHandler register.PostRegisterDetailsHandler
	// LoginPostResetPasswordHandler sets the operation handler for the post reset password operation
	LoginPostResetPasswordHandler login.PostResetPasswordHandler

	// ServeError is called when an error is received, there is a default handler
	// but you can set your own with this
	ServeError func(http.ResponseWriter, *http.Request, error)

	// ServerShutdown is called when the HTTP(S) server is shut down and done
	// handling all active connections and does not accept connections any more
	ServerShutdown func()

	// Custom command line argument groups with their descriptions
	CommandLineOptionsGroups []swag.CommandLineOptionsGroup

	// User defined logger function.
	Logger func(string, ...interface{})
}

// SetDefaultProduces sets the default produces media type
func (o *AuthServiceAPI) SetDefaultProduces(mediaType string) {
	o.defaultProduces = mediaType
}

// SetDefaultConsumes returns the default consumes media type
func (o *AuthServiceAPI) SetDefaultConsumes(mediaType string) {
	o.defaultConsumes = mediaType
}

// SetSpec sets a spec that will be served for the clients.
func (o *AuthServiceAPI) SetSpec(spec *loads.Document) {
	o.spec = spec
}

// DefaultProduces returns the default produces media type
func (o *AuthServiceAPI) DefaultProduces() string {
	return o.defaultProduces
}

// DefaultConsumes returns the default consumes media type
func (o *AuthServiceAPI) DefaultConsumes() string {
	return o.defaultConsumes
}

// Formats returns the registered string formats
func (o *AuthServiceAPI) Formats() strfmt.Registry {
	return o.formats
}

// RegisterFormat registers a custom format validator
func (o *AuthServiceAPI) RegisterFormat(name string, format strfmt.Format, validator strfmt.Validator) {
	o.formats.Add(name, format, validator)
}

// Validate validates the registrations in the AuthServiceAPI
func (o *AuthServiceAPI) Validate() error {
	var unregistered []string

	if o.JSONConsumer == nil {
		unregistered = append(unregistered, "JSONConsumer")
	}

	if o.JSONProducer == nil {
		unregistered = append(unregistered, "JSONProducer")
	}

	if o.RegisterGetCallbackGoogleHandler == nil {
		unregistered = append(unregistered, "register.GetCallbackGoogleHandler")
	}

	if o.RegisterGetRegisterConfirmationTokenHandler == nil {
		unregistered = append(unregistered, "register.GetRegisterConfirmationTokenHandler")
	}

	if o.LoginGetResetPasswordConfirmationTokenHandler == nil {
		unregistered = append(unregistered, "login.GetResetPasswordConfirmationTokenHandler")
	}

	if o.LoginGetResetPasswordRequestEmailHandler == nil {
		unregistered = append(unregistered, "login.GetResetPasswordRequestEmailHandler")
	}

	if o.LoginPostLoginHandler == nil {
		unregistered = append(unregistered, "login.PostLoginHandler")
	}

	if o.RegisterPostRegisterHandler == nil {
		unregistered = append(unregistered, "register.PostRegisterHandler")
	}

	if o.RegisterPostRegisterDetailsHandler == nil {
		unregistered = append(unregistered, "register.PostRegisterDetailsHandler")
	}

	if o.LoginPostResetPasswordHandler == nil {
		unregistered = append(unregistered, "login.PostResetPasswordHandler")
	}

	if len(unregistered) > 0 {
		return fmt.Errorf("missing registration: %s", strings.Join(unregistered, ", "))
	}

	return nil
}

// ServeErrorFor gets a error handler for a given operation id
func (o *AuthServiceAPI) ServeErrorFor(operationID string) func(http.ResponseWriter, *http.Request, error) {
	return o.ServeError
}

// AuthenticatorsFor gets the authenticators for the specified security schemes
func (o *AuthServiceAPI) AuthenticatorsFor(schemes map[string]spec.SecurityScheme) map[string]runtime.Authenticator {

	return nil

}

// Authorizer returns the registered authorizer
func (o *AuthServiceAPI) Authorizer() runtime.Authorizer {

	return nil

}

// ConsumersFor gets the consumers for the specified media types
func (o *AuthServiceAPI) ConsumersFor(mediaTypes []string) map[string]runtime.Consumer {

	result := make(map[string]runtime.Consumer)
	for _, mt := range mediaTypes {
		switch mt {

		case "application/json":
			result["application/json"] = o.JSONConsumer

		}

		if c, ok := o.customConsumers[mt]; ok {
			result[mt] = c
		}
	}
	return result

}

// ProducersFor gets the producers for the specified media types
func (o *AuthServiceAPI) ProducersFor(mediaTypes []string) map[string]runtime.Producer {

	result := make(map[string]runtime.Producer)
	for _, mt := range mediaTypes {
		switch mt {

		case "application/json":
			result["application/json"] = o.JSONProducer

		}

		if p, ok := o.customProducers[mt]; ok {
			result[mt] = p
		}
	}
	return result

}

// HandlerFor gets a http.Handler for the provided operation method and path
func (o *AuthServiceAPI) HandlerFor(method, path string) (http.Handler, bool) {
	if o.handlers == nil {
		return nil, false
	}
	um := strings.ToUpper(method)
	if _, ok := o.handlers[um]; !ok {
		return nil, false
	}
	if path == "/" {
		path = ""
	}
	h, ok := o.handlers[um][path]
	return h, ok
}

// Context returns the middleware context for the auth service API
func (o *AuthServiceAPI) Context() *middleware.Context {
	if o.context == nil {
		o.context = middleware.NewRoutableContext(o.spec, o, nil)
	}

	return o.context
}

func (o *AuthServiceAPI) initHandlerCache() {
	o.Context() // don't care about the result, just that the initialization happened

	if o.handlers == nil {
		o.handlers = make(map[string]map[string]http.Handler)
	}

	if o.handlers["GET"] == nil {
		o.handlers["GET"] = make(map[string]http.Handler)
	}
	o.handlers["GET"]["/callback-google"] = register.NewGetCallbackGoogle(o.context, o.RegisterGetCallbackGoogleHandler)

	if o.handlers["GET"] == nil {
		o.handlers["GET"] = make(map[string]http.Handler)
	}
	o.handlers["GET"]["/register-confirmation/{token}"] = register.NewGetRegisterConfirmationToken(o.context, o.RegisterGetRegisterConfirmationTokenHandler)

	if o.handlers["GET"] == nil {
		o.handlers["GET"] = make(map[string]http.Handler)
	}
	o.handlers["GET"]["/reset-password-confirmation/{token}"] = login.NewGetResetPasswordConfirmationToken(o.context, o.LoginGetResetPasswordConfirmationTokenHandler)

	if o.handlers["GET"] == nil {
		o.handlers["GET"] = make(map[string]http.Handler)
	}
	o.handlers["GET"]["/reset-password-request/{email}"] = login.NewGetResetPasswordRequestEmail(o.context, o.LoginGetResetPasswordRequestEmailHandler)

	if o.handlers["POST"] == nil {
		o.handlers["POST"] = make(map[string]http.Handler)
	}
	o.handlers["POST"]["/login"] = login.NewPostLogin(o.context, o.LoginPostLoginHandler)

	if o.handlers["POST"] == nil {
		o.handlers["POST"] = make(map[string]http.Handler)
	}
	o.handlers["POST"]["/register"] = register.NewPostRegister(o.context, o.RegisterPostRegisterHandler)

	if o.handlers["POST"] == nil {
		o.handlers["POST"] = make(map[string]http.Handler)
	}
	o.handlers["POST"]["/register-details"] = register.NewPostRegisterDetails(o.context, o.RegisterPostRegisterDetailsHandler)

	if o.handlers["POST"] == nil {
		o.handlers["POST"] = make(map[string]http.Handler)
	}
	o.handlers["POST"]["/reset-password"] = login.NewPostResetPassword(o.context, o.LoginPostResetPasswordHandler)

}

// Serve creates a http handler to serve the API over HTTP
// can be used directly in http.ListenAndServe(":8000", api.Serve(nil))
func (o *AuthServiceAPI) Serve(builder middleware.Builder) http.Handler {
	o.Init()

	if o.Middleware != nil {
		return o.Middleware(builder)
	}
	return o.context.APIHandler(builder)
}

// Init allows you to just initialize the handler cache, you can then recompose the middleware as you see fit
func (o *AuthServiceAPI) Init() {
	if len(o.handlers) == 0 {
		o.initHandlerCache()
	}
}

// RegisterConsumer allows you to add (or override) a consumer for a media type.
func (o *AuthServiceAPI) RegisterConsumer(mediaType string, consumer runtime.Consumer) {
	o.customConsumers[mediaType] = consumer
}

// RegisterProducer allows you to add (or override) a producer for a media type.
func (o *AuthServiceAPI) RegisterProducer(mediaType string, producer runtime.Producer) {
	o.customProducers[mediaType] = producer
}
