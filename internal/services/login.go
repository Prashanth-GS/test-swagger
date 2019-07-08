package services

import (
	"strings"
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
	if params.LoginRequest.Type == "" {
		return login.NewPostLoginBadRequest().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    400,
				Message: "Invalid Parameters",
			},
			Message: "Invalid parameters",
		})
	}
	logger.Log.Info(params.LoginRequest.Type)

	switch params.LoginRequest.Type {
	case "gl":
		return HandleGoogleLogin(params.HTTPRequest)
	case "fb":
		return HandleFacebookLogin(params.HTTPRequest)
	default:
		return loginOPUser(db, params)
	}
}

// HandleResetPasswordRequest Function
func HandleResetPasswordRequest(db *pg.DB, params *login.GetResetPasswordRequestEmailParams) middleware.Responder {
	logger.Log.Info("ResetPasswordRequest called with parameter:" + params.Email)

	user, err := database.SelectOneUserByEmail(db, params.Email)
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

	jwtToken, err := CreateJWT(params.Email, expTime)
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

	user, err := database.SelectOneUserByEmail(db, params.PasswordRequest.Email.(string))
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

	passwordHash := HashPassword(params.PasswordRequest.Password.(string))
	user.Password = passwordHash
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

func loginOPUser(db *pg.DB, params *login.PostLoginParams) middleware.Responder {
	user, err := database.SelectOneUserByEmail(db, params.LoginRequest.Email.(string))
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
	if !CheckPassword(user.Password, params.LoginRequest.Password.(string)) {
		logger.Log.Info("Incorrect password..")
		return login.NewPostLoginUnauthorized().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    401,
				Message: "Incorrect Password",
			},
			Message: "Incorrect Password",
		})
	}

	// Check if user is locked by super user
	if user.Locked {
		return login.NewPostLoginForbidden().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    403,
				Message: "User has been locked by super user",
			},
			Message: "Sorry, your login has been locked. Please contact admin for more information.",
		})
	}

	expirationTime := time.Now().Add(10 * time.Minute)
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
			Role:        user.Role,
		},
	})
}

// HandleRefreshJWT Function
func HandleRefreshJWT(params *login.GetRefreshTokenParams) middleware.Responder {
	authHeader := params.HTTPRequest.Header.Get("Authorization")
	authBearerArray := strings.Split(authHeader, " ")
	if len(authBearerArray) < 2 {
		return login.NewGetRefreshTokenUnauthorized().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    401,
				Message: "Token is Invalid",
			},
			Message: "Unauthorized, Please login to continue..",
		})
	}
	tknStr := authBearerArray[1]
	logger.Log.Info(tknStr)

	claims := &Claims{}
	tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
		return JWTKey, nil
	})
	if tkn.Valid {
		return login.NewGetRefreshTokenBadRequest().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    400,
				Message: "Token is still valid",
			},
			Message: "Bad Request, The token is still valid..",
		})
	}
	logger.Log.Error("Unauthorized.. Trying to Refresh Token..")
	if err != nil && !strings.Contains(err.Error(), "token is expired") {
		logger.Log.Error(err.Error())
		if err == jwt.ErrSignatureInvalid {
			return login.NewGetRefreshTokenUnauthorized().WithPayload(&models.GeneralResponse{
				Success: false,
				Error: &models.GeneralResponseError{
					Code:    401,
					Message: "Token is Invalid",
				},
				Message: "Unauthorized, Please login again to continue..",
			})
		}
		return login.NewGetRefreshTokenBadRequest().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    400,
				Message: "Token validation produced an error",
			},
			Message: "Bad Request, Please login again to continue..",
		})
	}

	// if (CURRENT TIME - EXPIRATION TIME) is GREATER THAN the ACCEPTED DURATION ==> Consider as a BAD REQUEST
	if time.Now().Sub(time.Unix(claims.ExpiresAt, 0)) > 5*time.Minute {
		logger.Log.Info("Expired, and delay is MORE than expected..")
		return login.NewGetRefreshTokenForbidden().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    403,
				Message: "Expired time is more than expected",
			},
			Message: "Forbidden, Please login again to continue..",
		})
	}
	logger.Log.Info("Expired, but delay is LESS than expected..")

	expirationTime := time.Now().Add(10 * time.Minute)
	claims.ExpiresAt = expirationTime.Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(JWTKey)
	if err != nil {
		return login.NewGetRefreshTokenInternalServerError().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    500,
				Message: "Token generation produced an error",
			},
			Message: "Something went wrong, please try again later..",
		})
	}

	return login.NewGetRefreshTokenOK().WithPayload(&models.LoginResponse{
		Success: true,
		Error:   nil,
		Data: &models.LoginResponseData{
			AccessToken: tokenString,
			ExpiresIn:   expirationTime.String(),
			Role:        nil,
		},
	})
}

func loginOAuthUser(db *pg.DB, userCreds *oauthResponse) middleware.Responder {
	user, err := database.SelectOneUserByOAuthID(db, userCreds.ID)
	if err != nil {
		logger.Log.Error(err.Error())
		if err == pg.ErrNoRows {
			return login.NewGetCallbackGoogleLoginNotFound().WithPayload(&models.GeneralResponse{
				Success: false,
				Error: &models.GeneralResponseError{
					Code:    404,
					Message: "Given ID is not found in the database",
				},
				Message: "Account is not registered, please register before logging in",
			})
		}
	}
	if !user.DetailsRegistered {
		logger.Log.Info("User has not completed Registration - User is available in the database, but he has not completed detailed registration..")
		return login.NewGetCallbackGoogleLoginForbidden().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    403,
				Message: "User has not completed Registration - User is available in the database, but he has not completed detailed registration",
			},
			Message: "Please complete organization registration and then, continue to Login.",
		})
	}

	// Check if user is locked by super user
	if user.Locked {
		return login.NewGetCallbackGoogleLoginForbidden().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    403,
				Message: "User has been locked by super user",
			},
			Message: "Sorry, your login has been locked. Please contact admin for more information.",
		})
	}

	token, err := CreateJWT(userCreds.ID, expTime)
	if err != nil {
		logger.Log.Error(err.Error())
		return login.NewGetCallbackGoogleLoginInternalServerError().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    500,
				Message: "An error occured when trying to create access token.",
			},
			Message: "Internal Server Error, please try again later.",
		})
	}

	return login.NewGetCallbackGoogleLoginOK().WithPayload(&models.LoginResponse{
		Success: true,
		Error:   nil,
		Data: &models.LoginResponseData{
			AccessToken: token,
			ExpiresIn:   expTime,
			Role:        user.Role,
		},
	})
}
