package services

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Prashanth-GS/test-swagger/internal/logger"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
)

// JWTKey from Config/environment
// Create the JWT key used to create the signature
var JWTKey = []byte(viper.GetString("jwt-secret"))

// Claims Struct
type Claims struct {
	Email string `json:"email"`
	jwt.StandardClaims
}

// Credentials Struct
type Credentials struct {
	Password string `json:"password"`
	Username string `json:"username"`
}

// CreateJWT Function
func CreateJWT(email string) (string, error) {
	logger.Log.Info(email)

	expirationTime := time.Now().Add(10 * time.Minute)
	claims := &Claims{
		Email: email,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(JWTKey)
	if err != nil {
		logger.Log.Error(err.Error())
	}

	logger.Log.Info(tokenString)
	return tokenString, nil
}

// ValidateJWT Function
func ValidateJWT(tknStr string) (*Claims, error) {
	claims := &Claims{}
	_, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
		return JWTKey, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			return claims, err
		}
		return claims, err
	}
	return claims, nil
}

/*
HandleOAuth Function
*/
func HandleOAuth(r *http.Request, oauthConf *oauth2.Config, oauthStateString string) middleware.Responder {
	URL, err := url.Parse(oauthConf.Endpoint.AuthURL)
	if err != nil {
		logger.Log.Error("Parse: " + err.Error())
	}
	logger.Log.Info(URL.String())
	parameters := url.Values{}
	parameters.Add("client_id", oauthConf.ClientID)
	parameters.Add("scope", strings.Join(oauthConf.Scopes, " "))
	parameters.Add("redirect_uri", oauthConf.RedirectURL)
	parameters.Add("response_type", "code")
	parameters.Add("state", oauthStateString)
	URL.RawQuery = parameters.Encode()
	url := URL.String()
	logger.Log.Info(url)

	return middleware.ResponderFunc(
		func(w http.ResponseWriter, pr runtime.Producer) {
			http.Redirect(w, r, url, http.StatusTemporaryRedirect)
		})
}
