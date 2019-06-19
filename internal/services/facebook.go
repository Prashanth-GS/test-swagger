package services

import (
	"net/http"

	"github.com/go-openapi/runtime/middleware"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
)

var (
	oauthConfFb = &oauth2.Config{
		ClientID:     "",
		ClientSecret: "",
		RedirectURL:  "http://localhost:9090/callback-fb",
		Scopes:       []string{"public_profile"},
		Endpoint:     facebook.Endpoint,
	}
	oauthStateStringFb = ""
)

/*
InitializeOAuthFacebook Function
*/
func InitializeOAuthFacebook() {
	oauthConfFb.ClientID = viper.GetString("facebook.clientID")
	oauthConfFb.ClientSecret = viper.GetString("facebook.clientSecret")
	oauthStateStringFb = viper.GetString("oauthStateString")
}

/*
HandleFacebookRegister Function
*/
func HandleFacebookRegister(r *http.Request) middleware.Responder {
	return HandleOAuth(r, oauthConfFb, oauthStateStringFb)
}

/*
HandleFacebookLogin Function
*/
func HandleFacebookLogin(r *http.Request) middleware.Responder {
	return HandleOAuth(r, oauthConfFb, oauthStateStringFb)
}
