package services

import (
	"time"

	"github.com/Prashanth-GS/test-swagger/internal/logger"
	"github.com/dgrijalva/jwt-go"
	"github.com/spf13/viper"
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
