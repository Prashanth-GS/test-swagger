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
	"golang.org/x/oauth2/google"
)

var (
	oauthConfGl = &oauth2.Config{
		ClientID:     "",
		ClientSecret: "",
		RedirectURL:  "",
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
		Endpoint:     google.Endpoint,
	}
	oauthStateStringGl  = ""
	registerRedirectURL = "http://localhost:9090/news-api/v1/callback-google"
	loginRedirectURL    = "http://localhost:9090/news-api/v1/callback-google-login"
)

/*
InitializeOAuthGoogle Function
*/
func InitializeOAuthGoogle() {
	oauthConfGl.ClientID = viper.GetString("google.clientID")
	oauthConfGl.ClientSecret = viper.GetString("google.clientSecret")
	oauthStateStringGl = viper.GetString("oauthStateString")
}

/*
HandleGoogleRegister Function
*/
func HandleGoogleRegister(r *http.Request) middleware.Responder {
	oauthConfGl.RedirectURL = registerRedirectURL
	return HandleOAuth(r, oauthConfGl, oauthStateStringGl)
}

/*
HandleGoogleLogin Function
*/
func HandleGoogleLogin(r *http.Request) middleware.Responder {
	oauthConfGl.RedirectURL = loginRedirectURL
	return HandleOAuth(r, oauthConfGl, oauthStateStringGl)
}

/*
CallBackFromGoogle Function
*/
func CallBackFromGoogle(db *pg.DB, r *http.Request) middleware.Responder {
	logger.Log.Info("Callback-gl..")

	state := r.FormValue("state")
	logger.Log.Info(state)
	if state != oauthStateStringGl {
		logger.Log.Info("invalid oauth state, expected " + oauthStateStringGl + ", got " + state + "\n")
		return register.NewGetCallbackGoogleBadRequest().WithPayload(&models.GeneralResponse{
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
			return register.NewGetCallbackGoogleUnauthorized().WithPayload(&models.GeneralResponse{
				Success: false,
				Error: &models.GeneralResponseError{
					Code:    401,
					Message: "User denied",
				},
				Message: "Unauthorized, Please authorize email.",
			})
		}
		return register.NewGetCallbackGoogleInternalServerError().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    500,
				Message: "toekn exchange failed",
			},
			Message: "Something went wrong please try again later.",
		})
	}
	token, err := oauthConfGl.Exchange(oauth2.NoContext, code)
	if err != nil {
		logger.Log.Error("oauthConfGl.Exchange() failed with " + err.Error() + "\n")
		return register.NewGetCallbackGoogleInternalServerError().WithPayload(&models.GeneralResponse{
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

	resp, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + url.QueryEscape(token.AccessToken))
	if err != nil {
		logger.Log.Error("Get: " + err.Error() + "\n")
		return register.NewGetCallbackGoogleInternalServerError().WithPayload(&models.GeneralResponse{
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
		return register.NewGetCallbackGoogleInternalServerError().WithPayload(&models.GeneralResponse{
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

	return registerOAuthUser(db, &userCred)
}
