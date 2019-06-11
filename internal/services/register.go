package services

import (
	"encoding/json"

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

	_, err := database.SelectOneUser(db, params.RegisterRequest.Email.(string))
	if err == nil {
		return register.NewPostRegisterForbidden().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    403,
				Message: "Given email is already registered",
			},
			Message: "Email is already registered, please continue to login or register using a different email address.",
		})
	}
	logger.Log.Error(err.Error())
	if err != pg.ErrNoRows {
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
	user := database.UserAuth{
		Email:                params.RegisterRequest.Email.(string),
		Password:             params.RegisterRequest.Password.(string),
		Role:                 "",
		Organization:         "",
		EmployeeCount:        0,
		Designation:          "",
		ConfirmationAccepted: false,
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

	// Send Email to the user..
	to := mail.NewEmail("GSOP Support", params.RegisterRequest.Email.(string))
	jwtToken, err := CreateJWT(params.RegisterRequest.Email.(string))
	if err != nil {
		logger.Log.Error(err.Error())
	}
	logger.Log.Info(jwtToken)
	message := mail.NewSingleEmail(
		helpers.FromAddress,
		helpers.RegiserConfEmailSubject,
		to,
		helpers.RegiserConfEmailContent,
		helpers.GetRegisterConfTemplate("http://localhost:9090/news-api/v1/register-confirmation/"+jwtToken),
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

// HandleRegisterDetails Function
func HandleRegisterDetails(db *pg.DB, params *register.PostRegisterDetailsParams) middleware.Responder {
	if params.RegisterRequest.Email == nil || params.RegisterRequest.Email == "" ||
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
	logger.Log.Info("Register Details called with parameters: " + params.RegisterRequest.Email.(string) +
		" " + params.RegisterRequest.Organization.(string) + " " + params.RegisterRequest.Designation.(string) +
		" " + string(params.RegisterRequest.EmployeeCount.(json.Number)))

	// Save the user to the database..
	empCount, err := params.RegisterRequest.EmployeeCount.(json.Number).Int64()
	if err != nil {
		logger.Log.Error(err.Error())
	}
	user, err := database.SelectOneUser(db, params.RegisterRequest.Email.(string))
	if err != nil {
		logger.Log.Error(err.Error())
		if err != nil {
			logger.Log.Error(err.Error())
			if err == pg.ErrNoRows {
				return register.NewPostRegisterDetailsNotFound().WithPayload(&models.GeneralResponse{
					Success: false,
					Error: &models.GeneralResponseError{
						Code:    404,
						Message: "Given email is not found in the database",
					},
					Message: "Email is not registered, please register before registering organization details",
				})
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
	claims, err := ValidateJWT(tknStr)
	if err != nil {
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
			Message: "Bad Request, Please reregister to continue..",
		})
	}

	user, err := database.SelectOneUser(db, claims.Email)
	if err != nil {
		logger.Log.Error(err.Error())
		if err == pg.ErrNoRows {
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
