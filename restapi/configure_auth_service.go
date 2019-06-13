// This file is safe to edit. Once it exists it will not be overwritten

package restapi

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"strings"

	errors "github.com/go-openapi/errors"
	runtime "github.com/go-openapi/runtime"
	middleware "github.com/go-openapi/runtime/middleware"
	"github.com/go-pg/pg"
	"github.com/rs/cors"
	"github.com/spf13/viper"

	"github.com/Prashanth-GS/test-swagger/internal/config"
	"github.com/Prashanth-GS/test-swagger/internal/database"
	"github.com/Prashanth-GS/test-swagger/internal/logger"
	"github.com/Prashanth-GS/test-swagger/internal/services"
	"github.com/Prashanth-GS/test-swagger/restapi/operations"
	"github.com/Prashanth-GS/test-swagger/restapi/operations/login"
	"github.com/Prashanth-GS/test-swagger/restapi/operations/register"
)

//go:generate swagger generate server --target ../../swg --name AuthService --spec ../spec/root.yml

func configureFlags(api *operations.AuthServiceAPI) {
	// api.CommandLineOptionsGroups = []swag.CommandLineOptionsGroup{ ... }
}

func configureAPI(api *operations.AuthServiceAPI) http.Handler {
	// configure the api here
	api.ServeError = errors.ServeError

	// Set your custom logger if needed. Default one is log.Printf
	// Expected interface func(string, ...interface{})
	//
	// Example:
	// api.Logger = log.Printf

	// Manual Configurations and setup here..
	config.InitializeViper()
	logger.InitializeZapCustomLogger()

	dbusername := viper.GetString("pgdb.username")
	dbpassword := viper.GetString("pgdb.password")
	dbName := viper.GetString("pgdb.database")
	logger.Log.Info(dbName)

	db := pg.Connect(&pg.Options{
		User:     dbusername,
		Password: dbpassword,
		Database: dbName,
	})
	// defer db.Close()

	_, err := db.Begin()
	if err != nil && strings.Contains(err.Error(), "database \""+dbName+"\" does not exist") {
		fmt.Println(err)
		os.Exit(1)
	}
	database.CreateUserAuthSchema(db)
	// Manual Configurations and setup here..

	api.JSONConsumer = runtime.JSONConsumer()

	api.JSONProducer = runtime.JSONProducer()

	if api.RegisterGetRegisterConfirmationTokenHandler == nil {
		api.RegisterGetRegisterConfirmationTokenHandler = register.GetRegisterConfirmationTokenHandlerFunc(func(params register.GetRegisterConfirmationTokenParams) middleware.Responder {
			return services.HandleRegisterConfirmation(db, &params)
		})
	}
	if api.LoginPostLoginHandler == nil {
		api.LoginPostLoginHandler = login.PostLoginHandlerFunc(func(params login.PostLoginParams) middleware.Responder {
			return services.HandleLogin(db, &params)
		})
	}
	if api.RegisterPostRegisterHandler == nil {
		api.RegisterPostRegisterHandler = register.PostRegisterHandlerFunc(func(params register.PostRegisterParams) middleware.Responder {
			return services.HandleRegister(db, &params)
		})
	}
	if api.RegisterPostRegisterDetailsHandler == nil {
		api.RegisterPostRegisterDetailsHandler = register.PostRegisterDetailsHandlerFunc(func(params register.PostRegisterDetailsParams) middleware.Responder {
			return services.HandleRegisterDetails(db, &params)
		})
	}
	if api.LoginGetResetPasswordRequestEmailHandler == nil {
		api.LoginGetResetPasswordRequestEmailHandler = login.GetResetPasswordRequestEmailHandlerFunc(func(params login.GetResetPasswordRequestEmailParams) middleware.Responder {
			return services.HandleResetPasswordRequest(db, &params)
		})
	}
	if api.LoginPostResetPasswordHandler == nil {
		api.LoginPostResetPasswordHandler = login.PostResetPasswordHandlerFunc(func(params login.PostResetPasswordParams) middleware.Responder {
			return services.HandleResetPassword(db, &params)
		})
	}
	if api.LoginGetResetPasswordConfirmationTokenHandler == nil {
		api.LoginGetResetPasswordConfirmationTokenHandler = login.GetResetPasswordConfirmationTokenHandlerFunc(func(params login.GetResetPasswordConfirmationTokenParams) middleware.Responder {
			return services.HandleResetPasswordConfirmation(&params)
		})
	}

	if api.LoginGetRefreshTokenHandler == nil {
		api.LoginGetRefreshTokenHandler = login.GetRefreshTokenHandlerFunc(func(params login.GetRefreshTokenParams) middleware.Responder {
			return services.HandleRefreshJWT(&params)
		})
	}

	api.ServerShutdown = func() {}

	return setupGlobalMiddleware(api.Serve(setupMiddlewares))
}

// The TLS configuration before HTTPS server starts.
func configureTLS(tlsConfig *tls.Config) {
	// Make all necessary changes to the TLS configuration here.
}

// As soon as server is initialized but not run yet, this function will be called.
// If you need to modify a config, store server instance to stop it individually later, this is the place.
// This function can be called multiple times, depending on the number of serving schemes.
// scheme value will be set accordingly: "http", "https" or "unix"
func configureServer(s *http.Server, scheme, addr string) {
}

// The middleware configuration is for the handler executors. These do not apply to the swagger.json document.
// The middleware executes after routing but before authentication, binding and validation
func setupMiddlewares(handler http.Handler) http.Handler {
	return handler
}

// The middleware configuration happens before anything, this middleware also applies to serving the swagger.json document.
// So this is a good place to plug in a panic handling middleware, logging and metrics
func setupGlobalMiddleware(handler http.Handler) http.Handler {
	handleCORS := cors.Default().Handler

	return handleCORS(handler)
}
