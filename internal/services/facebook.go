package services

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/Prashanth-GS/test-swagger/internal/logger"
	"github.com/Prashanth-GS/test-swagger/models"
	"github.com/Prashanth-GS/test-swagger/restapi/operations/register"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-pg/pg"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
)

var (
	oauthConfFb = &oauth2.Config{
		ClientID:     "",
		ClientSecret: "",
		RedirectURL:  "",
		Scopes:       []string{"public_profile"},
		Endpoint:     facebook.Endpoint,
	}
	oauthStateStringFb    = ""
	registerRedirectURLFb = "http://localhost:3000/callback/facebook"
	loginRedirectURLFb    = "http://localhost:3000/callback/login/facebook"
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
	oauthConfFb.RedirectURL = registerRedirectURLFb
	return HandleOAuth(r, oauthConfFb, oauthStateStringFb)
}

/*
HandleFacebookLogin Function
*/
func HandleFacebookLogin(r *http.Request) middleware.Responder {
	oauthConfFb.RedirectURL = loginRedirectURLFb
	return HandleOAuth(r, oauthConfFb, oauthStateStringFb)
}

/*
CallBackFromFacebook Function
*/
func CallBackFromFacebook(action string, db *pg.DB, r *http.Request) middleware.Responder {
	logger.Log.Info("Callback-fb..")

	state := r.FormValue("state")
	logger.Log.Info(state)
	if state != oauthStateStringFb {
		logger.Log.Info("invalid oauth state, expected " + oauthStateStringFb + ", got " + state + "\n")
		return register.NewGetCallbackFacebookBadRequest().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    400,
				Message: "invalid state string",
			},
			Message: "Bad Request, Please try again later.",
		})
	}

	code := r.FormValue("code")
	logger.Log.Info(code)

	if code == "" {
		logger.Log.Warn("Code not found..")
		reason := r.FormValue("error_reason")
		if reason == "user_denied" {
			return register.NewGetCallbackFacebookUnauthorized().WithPayload(&models.GeneralResponse{
				Success: false,
				Error: &models.GeneralResponseError{
					Code:    401,
					Message: "User denied",
				},
				Message: "Unauthorized, Please authorize email.",
			})
		}
		return register.NewGetCallbackFacebookInternalServerError().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    500,
				Message: "toekn exchange failed",
			},
			Message: "Something went wrong please try again later.",
		})
	}
	token, err := oauthConfFb.Exchange(oauth2.NoContext, code)
	if err != nil {
		logger.Log.Error("oauthConfFb.Exchange() failed with " + err.Error() + "\n")
		return register.NewGetCallbackFacebookInternalServerError().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    500,
				Message: "toekn exchange failed",
			},
			Message: "Something went wrong please try again later.",
		})
	}
	logger.Log.Info("TOKEN>> AccessToken>> " + token.AccessToken)
	logger.Log.Info("TOKEN>> Expiration Time>> " + token.Expiry.String())

	resp, err := http.Get("https://graph.facebook.com/me?access_token=" +
		url.QueryEscape(token.AccessToken) + "&fields=email")
	if err != nil {
		logger.Log.Error("Get: " + err.Error() + "\n")
		return register.NewGetCallbackFacebookInternalServerError().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    500,
				Message: "toekn exchange failed",
			},
			Message: "Something went wrong please try again later.",
		})
	}
	defer resp.Body.Close()

	response, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logger.Log.Error("ReadAll: " + err.Error() + "\n")
		return register.NewGetCallbackFacebookInternalServerError().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    500,
				Message: "toekn exchange failed",
			},
			Message: "Something went wrong please try again later.",
		})
	}
	logger.Log.Info("parseResponseBody: " + string(response) + "\n")

	userCred := oauthResponse{}
	json.Unmarshal(response, &userCred)
	logger.Log.Info(userCred.Email + " " + userCred.ID)

	if action == "register" {
		logger.Log.Info("Attempting to register user..")
		return registerOAuthUser(db, &userCred)
	}
	logger.Log.Info("Attempting to login user..")
	return loginOAuthUser(db, &userCred)
}
