package services

import (
	"encoding/json"

	"github.com/Prashanth-GS/test-swagger/internal/database"
	"github.com/Prashanth-GS/test-swagger/internal/helpers"
	"github.com/Prashanth-GS/test-swagger/internal/logger"
	"github.com/Prashanth-GS/test-swagger/models"
	"github.com/Prashanth-GS/test-swagger/restapi/operations/register"

	"github.com/go-openapi/runtime/middleware"
	"github.com/go-pg/pg"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
	"github.com/spf13/viper"
)

// HandleRegister Function
func HandleRegister(db *pg.DB, params *register.PostRegisterParams) middleware.Responder {
	logger.Log.Info("Register called with parameters: " + params.RegisterRequest.Type +
		" " + params.RegisterRequest.Email.(string) + " " + params.RegisterRequest.Password.(string))

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
	err := database.AddNewUser(db, &user)
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
	to := mail.NewEmail("Example User", params.RegisterRequest.Email.(string))
	jwtToken, err := CreateJWT(params)
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

	claims, response, err := ValidateJWT(tknStr)
	if err != nil {
		return response
	}
	logger.Log.Info(claims.Email)

	user, err := database.SelectOneUser(db, claims.Email)
	if err != nil {
		logger.Log.Error(err.Error())
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