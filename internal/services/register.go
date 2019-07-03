package services

import (
	"encoding/json"
	"strings"

	"github.com/Prashanth-GS/test-swagger/internal/database"
	"github.com/Prashanth-GS/test-swagger/internal/helpers"
	"github.com/Prashanth-GS/test-swagger/internal/logger"
	"github.com/Prashanth-GS/test-swagger/models"
	"github.com/Prashanth-GS/test-swagger/restapi/operations/register"
	"github.com/dgrijalva/jwt-go"

	"github.com/go-openapi/runtime/middleware"
	"github.com/go-pg/pg"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
	"github.com/spf13/viper"
)

// HandleRegister Function
func HandleRegister(db *pg.DB, params *register.PostRegisterParams) middleware.Responder {
	if params.RegisterRequest.Type == "" {
		return register.NewPostRegisterBadRequest().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    400,
				Message: "Invalid Parameters",
			},
			Message: "Invalid parameters",
		})
	}
	logger.Log.Info(params.RegisterRequest.Type)

	switch params.RegisterRequest.Type {
	case "gl":
		return HandleGoogleRegister(params.HTTPRequest)
	case "fb":
		return HandleFacebookRegister(params.HTTPRequest)
	default:
		if params.RegisterRequest.Email == nil || params.RegisterRequest.Email == "" ||
			params.RegisterRequest.Password == nil || params.RegisterRequest.Password == "" ||
			params.RegisterRequest.Type == "" {
			logger.Log.Error("BadRequest - Invalid parameters..")
			return register.NewPostRegisterBadRequest().WithPayload(&models.GeneralResponse{
				Success: false,
				Error: &models.GeneralResponseError{
					Code:    400,
					Message: "Invalid Parameters",
				},
				Message: "Invalid parameters",
			})
		}
		logger.Log.Info("Register called with parameters: " + params.RegisterRequest.Type +
			" " + params.RegisterRequest.Email.(string) + " " + params.RegisterRequest.Password.(string))
		return registerOPUser(db, params)
	}
}

// HandleRegisterDetails Function
func HandleRegisterDetails(db *pg.DB, params *register.PostRegisterDetailsParams) middleware.Responder {
	authHeader := params.HTTPRequest.Header.Get("Authorization")
	logger.Log.Info(authHeader)
	claims, err := ValidateJWT(strings.Split(authHeader, " ")[1])
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			return register.NewPostRegisterDetailsUnauthorized().WithPayload(&models.GeneralResponse{
				Success: false,
				Error: &models.GeneralResponseError{
					Code:    401,
					Message: "Token is Invalid",
				},
				Message: "Unauthorized, Please reregister to continue..",
			})
		}
		return register.NewPostRegisterDetailsBadRequest().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    400,
				Message: "Token validation produced an error",
			},
			Message: "Bad Request, Please reregister to continue..",
		})
	}
	if params.RegisterRequest.Name == nil || params.RegisterRequest.Name == "" ||
		params.RegisterRequest.Organization == nil || params.RegisterRequest.Organization == "" ||
		params.RegisterRequest.Designation == nil || params.RegisterRequest.Designation == "" ||
		params.RegisterRequest.EmployeeCount == nil || params.RegisterRequest.EmployeeCount == "" {
		logger.Log.Error("BadRequest - Invalid parameters..")
		return register.NewPostRegisterBadRequest().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    400,
				Message: "Invalid Parameters",
			},
			Message: "Invalid parameters",
		})
	}
	logger.Log.Info("Register Details called with parameters: " + params.RegisterRequest.Organization.(string) +
		" " + params.RegisterRequest.Designation.(string) + " " + string(params.RegisterRequest.EmployeeCount.(json.Number)))

	// Save the user to the database..
	empCount, err := params.RegisterRequest.EmployeeCount.(json.Number).Int64()
	if err != nil {
		logger.Log.Error(err.Error())
		return register.NewPostRegisterDetailsBadRequest().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    400,
				Message: "Bad Request, expected an integer as Employee Count, but got something else",
			},
			Message: "BadRequest, Please enter a number for Employee Count field.",
		})
	}
	user, err := database.SelectOneUserByEmail(db, claims.Email)
	if err != nil {
		logger.Log.Error(err.Error())
		if err == pg.ErrNoRows {
			user, err = database.SelectOneUserByOAuthID(db, claims.Email)
			if err != nil {
				logger.Log.Error(err.Error())
				if err == pg.ErrNoRows {
					return register.NewPostRegisterDetailsNotFound().WithPayload(&models.GeneralResponse{
						Success: false,
						Error: &models.GeneralResponseError{
							Code:    404,
							Message: "Given account is not found in the database",
						},
						Message: "Account is not registered, please register before registering organization details",
					})
				}
			}
		}
	}

	if !user.ConfirmationAccepted {
		logger.Log.Info(user.Email + "User has not confirmed the email address..")
		return register.NewPostRegisterDetailsForbidden().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    403,
				Message: "Forbidden, the user has not accepted the email confirmation",
			},
			Message: "Please confirm your email address to proceed",
		})
	}

	if user.DetailsRegistered {
		logger.Log.Info(user.Email + "User has already registered organization details..")
		return register.NewPostRegisterDetailsForbidden().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    403,
				Message: "Forbidden, the user already registered organization details",
			},
			Message: "Already registered, please login to continue",
		})
	}

	user.Role = "user"
	user.Name = params.RegisterRequest.Name.(string)
	user.EmployeeCount = int(empCount)
	user.Organization = params.RegisterRequest.Organization.(string)
	user.Designation = params.RegisterRequest.Designation.(string)
	user.DetailsRegistered = true

	err = database.UpdateUser(db, user)
	if err != nil {
		logger.Log.Error(err.Error())
		return register.NewPostRegisterDetailsInternalServerError().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    500,
				Message: err.Error(),
			},
			Message: "Error occurred when trying to process the request",
		})
	}
	logger.Log.Info("Registration Details added..")

	return register.NewPostRegisterDetailsOK().WithPayload(&models.GeneralResponse{
		Success: true,
		Error:   nil,
		Message: "User Registration success, Continue to Login..",
	})
}

// HandleRegisterConfirmation Function
func HandleRegisterConfirmation(db *pg.DB, params *register.GetRegisterConfirmationTokenParams) middleware.Responder {
	logger.Log.Info("Register Confirmation called with parameters: " + params.Token)

	// Process JWT
	tknStr := params.Token
	claims, errJWT := ValidateJWT(tknStr)
	user, err := database.SelectOneUserByEmail(db, claims.Email)
	if err != nil {
		logger.Log.Error(err.Error())
		if err == pg.ErrNoRows {
			user, err = database.SelectOneUserByOAuthID(db, claims.Email)
			if err == nil && user.Mode == "oa" {
				return register.NewGetRegisterConfirmationTokenOK().WithPayload(&models.GeneralResponse{
					Success: true,
					Error:   nil,
					Message: "User Confirmation success, Proceed to Details Registration..",
				})
			}
			return register.NewGetRegisterConfirmationTokenNotFound().WithPayload(&models.GeneralResponse{
				Success: false,
				Error: &models.GeneralResponseError{
					Code:    404,
					Message: err.Error(),
				},
				Message: "User does not exist, please register to continue.",
			})
		}
		return register.NewGetRegisterConfirmationTokenInternalServerError().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    500,
				Message: err.Error(),
			},
			Message: "Error occurred when trying to process the request",
		})
	}
	if errJWT != nil {
		user.ConfirmationAccepted = false
		user.ConfirmationExpired = true
		user.DetailsRegistered = false

		err = database.UpdateUser(db, user)
		if err != nil {
			logger.Log.Error(err.Error())
			return register.NewPostRegisterDetailsInternalServerError().WithPayload(&models.GeneralResponse{
				Success: false,
				Error: &models.GeneralResponseError{
					Code:    500,
					Message: err.Error(),
				},
				Message: "Error occurred when trying to process the request",
			})
		}
		if err == jwt.ErrSignatureInvalid {
			return register.NewGetRegisterConfirmationTokenUnauthorized().WithPayload(&models.GeneralResponse{
				Success: false,
				Error: &models.GeneralResponseError{
					Code:    401,
					Message: "Token is Invalid",
				},
				Message: "Unauthorized, Please reregister to continue..",
			})
		}
		return register.NewGetRegisterConfirmationTokenBadRequest().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    400,
				Message: "Token validation produced an error",
			},
			Message: "Session Expired, Please reregister to continue..",
		})
	}

	if user.DetailsRegistered {
		logger.Log.Info("User has already registered organization information..")
		return register.NewGetRegisterConfirmationTokenBadRequest().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    400,
				Message: "User has already registered organization information",
			},
			Message: "Organization details already submitted, please continue to login.",
		})
	}

	user.ConfirmationAccepted = true
	user.ConfirmationExpired = false
	user.DetailsRegistered = false

	err = database.UpdateUser(db, user)
	if err != nil {
		logger.Log.Error(err.Error())
		return register.NewPostRegisterDetailsInternalServerError().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    500,
				Message: err.Error(),
			},
			Message: "Error occurred when trying to process the request",
		})
	}

	return register.NewGetRegisterConfirmationTokenOK().WithPayload(&models.GeneralResponse{
		Success: true,
		Error:   nil,
		Message: "User Confirmation success, Proceed to Details Registration..",
	})
}

func registerOPUser(db *pg.DB, params *register.PostRegisterParams) middleware.Responder {
	existingUser, err := database.SelectOneUserByEmail(db, params.RegisterRequest.Email.(string))
	if err == nil {
		if existingUser.ConfirmationAccepted || existingUser.DetailsRegistered {
			return register.NewPostRegisterForbidden().WithPayload(&models.GeneralResponse{
				Success: false,
				Error: &models.GeneralResponseError{
					Code:    403,
					Message: "Given email is already registered",
				},
				Message: "Email is already registered, please continue to login or register using a different email address.",
			})
		}
		if existingUser.ConfirmationExpired {
			return registerProcess("existing", db, params)
		}
		return register.NewPostRegisterForbidden().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    403,
				Message: "Given email is already registered, but need to verify the email address",
			},
			Message: "Email is already registered, please verify the email address to continue.",
		})
	}
	if err != nil && err != pg.ErrNoRows {
		logger.Log.Error(err.Error())
		return register.NewPostRegisterInternalServerError().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    500,
				Message: "Error while querying the database",
			},
			Message: "Something went wrong, please try again later.",
		})
	}

	// Save the user to the database..
	return registerProcess("new", db, params)
}

func registerProcess(userStatus string, db *pg.DB, params *register.PostRegisterParams) middleware.Responder {
	user := database.UserAuth{
		Email:                params.RegisterRequest.Email.(string),
		Password:             params.RegisterRequest.Password.(string),
		Mode:                 "op",
		OAuthID:              "",
		Role:                 "",
		Name:                 "",
		Organization:         "",
		EmployeeCount:        0,
		Designation:          "",
		ConfirmationAccepted: false,
		ConfirmationExpired:  false,
		DetailsRegistered:    false,
	}
	var err error
	if userStatus == "new" {
		err = database.AddNewUser(db, &user)
	} else {
		existingUser, err := database.SelectOneUserByEmail(db, params.RegisterRequest.Email.(string))
		if err != nil {
			logger.Log.Error(err.Error())
			return register.NewPostRegisterInternalServerError().WithPayload(&models.GeneralResponse{
				Success: false,
				Error: &models.GeneralResponseError{
					Code:    500,
					Message: err.Error(),
				},
				Message: "Error occurred when trying to process the request",
			})
		}
		existingUser.Email = params.RegisterRequest.Email.(string)
		existingUser.Password = params.RegisterRequest.Password.(string)
		existingUser.ConfirmationAccepted = false
		existingUser.ConfirmationExpired = false
		err = database.UpdateUser(db, existingUser)
	}
	if err != nil {
		logger.Log.Error(err.Error())
		return register.NewPostRegisterInternalServerError().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    500,
				Message: err.Error(),
			},
			Message: "Error occurred when trying to process the request",
		})
	}
	logger.Log.Info("User added to database..")

	// Send Email to the user..
	to := mail.NewEmail("GSOP Support", params.RegisterRequest.Email.(string))
	jwtToken, err := CreateJWT(params.RegisterRequest.Email.(string), expTime)
	if err != nil {
		logger.Log.Error(err.Error())
	}
	logger.Log.Info(jwtToken)
	message := mail.NewSingleEmail(
		helpers.FromAddress,
		helpers.RegiserConfEmailSubject,
		to,
		helpers.RegiserConfEmailContent,
		helpers.GetRegisterConfTemplate("http://localhost:3000/selections/"+jwtToken),
	)
	client := sendgrid.NewSendClient(viper.GetString("sendgrid-apikey"))
	_, err = client.Send(message)
	if err != nil {
		logger.Log.Info(err.Error())
		return register.NewPostRegisterInternalServerError().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    500,
				Message: err.Error(),
			},
			Message: "Error occurred when trying to send the email",
		})
	}
	logger.Log.Info("Registration Confirmation Email Sent..")

	return register.NewPostRegisterOK().WithPayload(&models.GeneralResponse{
		Success: true,
		Error:   nil,
		Message: "Registration Initial Step Success, Email Confirmation Sent..",
	})
}

func registerOAuthUser(db *pg.DB, userCreds *oauthResponse) middleware.Responder {
	existingUser, err := database.SelectOneUserByOAuthID(db, userCreds.ID)
	if err == nil {
		if existingUser.DetailsRegistered {
			return register.NewPostRegisterForbidden().WithPayload(&models.GeneralResponse{
				Success: false,
				Error: &models.GeneralResponseError{
					Code:    403,
					Message: "Given account is already registered",
				},
				Message: "The Account is already registered, please continue to login or register using a different account.",
			})
		}
	}
	if err != nil && err == pg.ErrNoRows {
		user := database.UserAuth{
			Email:                "",
			Password:             "",
			Mode:                 "oa",
			OAuthID:              userCreds.ID,
			Role:                 "",
			Name:                 "",
			Organization:         "",
			EmployeeCount:        0,
			Designation:          "",
			ConfirmationAccepted: true,
			ConfirmationExpired:  false,
			DetailsRegistered:    false,
		}
		err = database.AddNewUser(db, &user)
		if err != nil {
			logger.Log.Error(err.Error())
			return register.NewPostRegisterInternalServerError().WithPayload(&models.GeneralResponse{
				Success: false,
				Error: &models.GeneralResponseError{
					Code:    500,
					Message: err.Error(),
				},
				Message: "Error occurred when trying to process the request",
			})
		}
		logger.Log.Info("User added to database..")
	}

	token, err := CreateJWT(userCreds.ID, expTime)
	if err != nil {
		logger.Log.Error(err.Error())
		return register.NewPostRegisterInternalServerError().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    500,
				Message: err.Error(),
			},
			Message: "Error occurred when trying to create access token",
		})
	}

	return register.NewGetCallbackGoogleOK().WithPayload(&models.LoginResponse{
		Success: true,
		Error:   nil,
		Data: &models.LoginResponseData{
			AccessToken: token,
			ExpiresIn:   "5 mins",
			Role:        nil,
		},
	})
}
