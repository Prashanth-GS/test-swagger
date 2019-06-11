package services

import (
	"time"

	"github.com/Prashanth-GS/test-swagger/internal/database"
	"github.com/Prashanth-GS/test-swagger/internal/helpers"
	"github.com/Prashanth-GS/test-swagger/internal/logger"
	"github.com/Prashanth-GS/test-swagger/models"
	"github.com/Prashanth-GS/test-swagger/restapi/operations/login"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-pg/pg"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
	"github.com/spf13/viper"
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
	if !user.DetailsRegistered {
		logger.Log.Info("User has not completed Registration - User is available in the database, but he has not completed detailed registration..")
		return login.NewPostLoginForbidden().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    403,
				Message: "User has not completed Registration - User is available in the database, but he has not completed detailed registration",
			},
			Message: "Please complete organization registration and then, continue to Login.",
		})
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

// HandleResetPasswordRequest Function
func HandleResetPasswordRequest(db *pg.DB, params *login.GetResetPasswordRequestEmailParams) middleware.Responder {
	logger.Log.Info("ResetPasswordRequest called with parameter:" + params.Email)

	user, err := database.SelectOneUser(db, params.Email)
	if err != nil {
		logger.Log.Error(err.Error())
		if err == pg.ErrNoRows {
			return login.NewGetResetPasswordRequestEmailNotFound().WithPayload(&models.GeneralResponse{
				Success: false,
				Error: &models.GeneralResponseError{
					Code:    404,
					Message: "Given email is not found in the database",
				},
				Message: "Email is not registered, please register before logging in",
			})
		}
	}
	if !user.DetailsRegistered {
		logger.Log.Info("User has not completed Registration - User is available in the database, but he has not completed detailed registration..")
		return login.NewGetResetPasswordRequestEmailForbidden().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    403,
				Message: "User has not completed Registration - User is available in the database, but he has not completed detailed registration",
			},
			Message: "Please complete organization registration and then, continue to Login.",
		})
	}

	jwtToken, err := CreateJWT(params.Email)
	if err != nil {
		logger.Log.Error(err.Error())
		return login.NewGetResetPasswordRequestEmailInternalServerError().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    500,
				Message: "Error while creating JWT",
			},
			Message: "Something went wrong trying to send email, please try again later.",
		})
	}
	logger.Log.Info(jwtToken)

	message := mail.NewSingleEmail(
		helpers.FromAddress,
		helpers.RPEmailSubject,
		mail.NewEmail("GSOP Support", params.Email),
		helpers.RPEmailContent,
		helpers.GetResetPasswordTemplate("http://localhost:9090/news-api/v1/reset-password-confirmation/"+jwtToken),
	)
	client := sendgrid.NewSendClient(viper.GetString("sendgrid-apikey"))
	_, err = client.Send(message)
	if err != nil {
		logger.Log.Info(err.Error())
		return login.NewGetResetPasswordRequestEmailInternalServerError().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    500,
				Message: "Error while sending Email",
			},
			Message: "Something went wrong trying to send email, please try again later.",
		})
	}
	logger.Log.Info("Registration Confirmation Email Sent..")

	return login.NewGetResetPasswordRequestEmailOK().WithPayload(&models.GeneralResponse{
		Success: true,
		Error:   nil,
		Message: "Email with link to reset password is sent.",
	})
}

// HandleResetPassword Function
func HandleResetPassword(db *pg.DB, params *login.PostResetPasswordParams) middleware.Responder {
	logger.Log.Info("Reset Password called with parameters: " + params.PasswordRequest.Email.(string) +
		" " + params.PasswordRequest.Password.(string))

	user, err := database.SelectOneUser(db, params.PasswordRequest.Email.(string))
	if err != nil {
		logger.Log.Error(err.Error())
		if err != nil {
			logger.Log.Error(err.Error())
			if err == pg.ErrNoRows {
				return login.NewPostResetPasswordNotFound().WithPayload(&models.GeneralResponse{
					Success: false,
					Error: &models.GeneralResponseError{
						Code:    404,
						Message: "Given email is not found in the database",
					},
					Message: "Email is not registered, please register before logging in",
				})
			}
		}
	}
	if !user.DetailsRegistered {
		logger.Log.Info("User has not completed Registration - User is available in the database, but he has not completed detailed registration..")
		return login.NewPostResetPasswordForbidden().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    403,
				Message: "User has not completed Registration - User is available in the database, but he has not completed detailed registration",
			},
			Message: "Please complete organization registration and then, continue to Login.",
		})
	}

	user.Password = params.PasswordRequest.Password.(string)
	err = database.UpdateUser(db, user)
	if err != nil {
		logger.Log.Error(err.Error())
		return login.NewPostResetPasswordInternalServerError().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    500,
				Message: err.Error(),
			},
			Message: "Error occurred when trying to process the request",
		})
	}
	logger.Log.Info("New Password saved to database..")

	return login.NewPostResetPasswordOK().WithPayload(&models.GeneralResponse{
		Success: true,
		Error:   nil,
		Message: "New Password successfully added.",
	})
}

// HandleResetPasswordConfirmation Function
func HandleResetPasswordConfirmation(params *login.GetResetPasswordConfirmationTokenParams) middleware.Responder {
	logger.Log.Info("ResetPasswordConfirmation called with Parameter: " + params.Token)

	claims, err := ValidateJWT(params.Token)
	if err != nil {
		logger.Log.Error(err.Error())
		if err == jwt.ErrSignatureInvalid {
			return login.NewGetResetPasswordConfirmationTokenUnauthorized().WithPayload(&models.GeneralResponse{
				Success: false,
				Error: &models.GeneralResponseError{
					Code:    401,
					Message: "Token is Invalid",
				},
				Message: "Unauthorized, Please request again to continue..",
			})
		}
		return login.NewGetResetPasswordConfirmationTokenBadRequest().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    400,
				Message: "Token validation produced an error",
			},
			Message: "Bad Request, Please try again to continue..",
		})
	}

	return login.NewGetResetPasswordConfirmationTokenOK().WithPayload(&models.UserEmailResponse{
		Success: true,
		Error:   nil,
		Data: &models.UserEmailResponseData{
			Email:   claims.Email,
			Message: "Reset Password confirmation successful, proceed to password reset.",
		},
	})
}
