package services

import (
	"time"

	"github.com/Prashanth-GS/test-swagger/internal/database"
	"github.com/Prashanth-GS/test-swagger/internal/logger"
	"github.com/Prashanth-GS/test-swagger/models"
	"github.com/Prashanth-GS/test-swagger/restapi/operations/login"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-pg/pg"
)

// HandleLogin Function
func HandleLogin(db *pg.DB, params *login.PostLoginParams) middleware.Responder {
	logger.Log.Info("Login called with parameters: " + params.LoginRequest.Type +
		" " + params.LoginRequest.Email.(string) + " " + params.LoginRequest.Password.(string))

	user, err := database.SelectOneUser(db, params.LoginRequest.Email.(string))
	if err != nil {
		logger.Log.Error(err.Error())
		if err == pg.ErrNoRows {
			return login.NewPostLoginNotFound().WithPayload(&models.GeneralResponse{
				Success: false,
				Error: &models.GeneralResponseError{
					Code:    404,
					Message: "Given email is not found in the database",
				},
				Message: "Email is not registered, please register before logging in",
			})
		}
	}
	if user.Password != params.LoginRequest.Password.(string) {
		return login.NewPostLoginUnauthorized().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    401,
				Message: "Incorrect Password",
			},
			Message: "Incorrect Password",
		})
	}
	expirationTime := time.Now().Add(1 * time.Minute)
	claims := &Claims{
		Email: params.LoginRequest.Email.(string),
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(JWTKey)
	if err != nil {
		logger.Log.Error(err.Error())
		return login.NewPostLoginInternalServerError().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    500,
				Message: "Something went wrong. Please try again.",
			},
			Message: "Something went wrong. Please try again.",
		})
	}

	logger.Log.Info(tokenString)

	return login.NewPostLoginOK().WithPayload(&models.LoginResponse{
		Success: true,
		Error:   nil,
		Data: &models.LoginResponseData{
			AccessToken: tokenString,
			ExpiresIn:   expirationTime.String(),
		},
	})
}
