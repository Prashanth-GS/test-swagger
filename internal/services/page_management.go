package services

import (
	"strings"

	"github.com/Prashanth-GS/test-swagger/internal/database"
	"github.com/Prashanth-GS/test-swagger/internal/logger"
	"github.com/Prashanth-GS/test-swagger/models"
	"github.com/Prashanth-GS/test-swagger/restapi/operations/page_management"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-pg/pg"
)

// HandleGetDashboardSetup Function
func HandleGetDashboardSetup(db *pg.DB, params *page_management.GetDashboardDetailsEmailTypeParams) middleware.Responder {
	logger.Log.Info("Get Dashboard Setup Details called..")

	// Check for the access Toke and verify that it is valid and belongs to a super user
	authHeader := params.HTTPRequest.Header.Get("Authorization")
	logger.Log.Info(authHeader)
	authBearerArray := strings.Split(authHeader, " ")
	if len(authBearerArray) < 2 {
		return page_management.NewGetDashboardDetailsEmailTypeUnauthorized().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    401,
				Message: "Token is Invalid",
			},
			Message: "Unauthorized, Please login to continue..",
		})
	}
	claims, err := ValidateJWT(authBearerArray[1])
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			return page_management.NewGetDashboardDetailsEmailTypeUnauthorized().WithPayload(&models.GeneralResponse{
				Success: false,
				Error: &models.GeneralResponseError{
					Code:    401,
					Message: "Token is Invalid",
				},
				Message: "Unauthorized, Please login to continue..",
			})
		}
		return page_management.NewGetDashboardDetailsEmailTypeBadRequest().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    400,
				Message: "Token validation produced an error",
			},
			Message: "Bad Request, Please login to continue..",
		})
	}

	user, err := database.SelectOneUserByEmail(db, claims.Email)
	if err != nil {
		logger.Log.Error(err.Error())
		if err == pg.ErrNoRows {
			if err == pg.ErrNoRows {
				return page_management.NewGetDashboardDetailsEmailTypeNotFound().WithPayload(&models.GeneralResponse{
					Success: false,
					Error: &models.GeneralResponseError{
						Code:    404,
						Message: "Given account is not found in the database",
					},
					Message: "Account is not registered, please register as a super user..",
				})
			}
		}
		return page_management.NewGetDashboardDetailsEmailTypeInternalServerError().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    500,
				Message: err.Error(),
			},
			Message: "Error occurred when trying to process the request",
		})
	}

	if user.Role != "super" {
		logger.Log.Info("user " + claims.Email + " is not a super user")
		if user.Email != claims.Email {
			logger.Log.Info("Logged in user is neither a super user or the owner of the information..")
			return page_management.NewGetDashboardDetailsEmailTypeForbidden().WithPayload(&models.GeneralResponse{
				Success: false,
				Error: &models.GeneralResponseError{
					Code:    403,
					Message: "user " + claims.Email + " is not a super user of the owner of requested information",
				},
				Message: "Forbidden, Please login as super user or request your own information to continue the request..",
			})
		}
	}
	logger.Log.Info("Type: " + params.Type + " \nEmail: " + params.Email)

	if params.Type == "" || params.Email == "" {
		logger.Log.Info("Type: " + params.Type + " \nEmail: " + params.Email)
		return page_management.NewGetDashboardDetailsEmailTypeBadRequest().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    403,
				Message: "Invalid parameters",
			},
			Message: "Bad Request, Invalid Parameters..",
		})
	}

	var userDetails *database.UserAuth
	if params.Type == "op" {
		userDetails, err = database.SelectOneUserByEmail(db, params.Email)
		if err != nil {
			logger.Log.Error(err.Error())
			if err == pg.ErrNoRows {
				return page_management.NewGetDashboardDetailsEmailTypeNotFound().WithPayload(&models.GeneralResponse{
					Success: false,
					Error: &models.GeneralResponseError{
						Code:    404,
						Message: "No op user for given email \"" + params.Email + "\" was found",
					},
					Message: "No user for given email \"" + params.Email + "\" was found",
				})
			}
			return page_management.NewGetDashboardDetailsEmailTypeInternalServerError().WithPayload(&models.GeneralResponse{
				Success: false,
				Error: &models.GeneralResponseError{
					Code:    500,
					Message: err.Error(),
				},
				Message: "Error occurred when trying to process the request",
			})
		}
	} else {
		userDetails, err = database.SelectOneUserByOAuthID(db, params.Email)
		if err != nil {
			logger.Log.Error(err.Error())
			if err == pg.ErrNoRows {
				return page_management.NewGetDashboardDetailsEmailTypeNotFound().WithPayload(&models.GeneralResponse{
					Success: false,
					Error: &models.GeneralResponseError{
						Code:    404,
						Message: "No oauth user for given oauthid \"" + params.Email + "\" was found",
					},
					Message: "No user for given oauthid \"" + params.Email + "\" was found",
				})
			}
			return page_management.NewGetDashboardDetailsEmailTypeInternalServerError().WithPayload(&models.GeneralResponse{
				Success: false,
				Error: &models.GeneralResponseError{
					Code:    500,
					Message: err.Error(),
				},
				Message: "Error occurred when trying to process the request",
			})
		}
	}

	return page_management.NewGetDashboardDetailsEmailTypeOK().WithPayload(&models.DashboardDetailsResponse{
		Success: true,
		Error:   nil,
		Data: &models.DashboardDetailsResponseData{
			UserRef:           params.Email,
			UserType:          params.Type,
			Organization:      userDetails.Organization,
			LogoURL:           userDetails.LogoURL,
			BgColor:           userDetails.BackgroundColor,
			FontColor:         userDetails.FontColor,
			NewsfeedBGColor:   userDetails.NewsfeedBackgroundColor,
			NewsfeedFontColor: userDetails.NewsfeedFontColor,
		},
	})
}

// HandlePostDashboardSetup Function
func HandlePostDashboardSetup(db *pg.DB, params *page_management.PostDashboardSetupParams) middleware.Responder {
	logger.Log.Info("Post Dashboard Setup Details called..")

	// Check for the access Toke and verify that it is valid and belongs to a super user
	authHeader := params.HTTPRequest.Header.Get("Authorization")
	logger.Log.Info(authHeader)
	authBearerArray := strings.Split(authHeader, " ")
	if len(authBearerArray) < 2 {
		return page_management.NewPostDashboardSetupUnauthorized().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    401,
				Message: "Token is Invalid",
			},
			Message: "Unauthorized, Please login to continue..",
		})
	}
	claims, err := ValidateJWT(authBearerArray[1])
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			return page_management.NewPostDashboardSetupUnauthorized().WithPayload(&models.GeneralResponse{
				Success: false,
				Error: &models.GeneralResponseError{
					Code:    401,
					Message: "Token is Invalid",
				},
				Message: "Unauthorized, Please login to continue..",
			})
		}
		return page_management.NewPostDashboardSetupBadRequest().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    400,
				Message: "Token validation produced an error",
			},
			Message: "Bad Request, Please login to continue..",
		})
	}

	superUser, err := database.SelectOneUserByEmail(db, claims.Email)
	if err != nil {
		logger.Log.Error(err.Error())
		if err == pg.ErrNoRows {
			if err == pg.ErrNoRows {
				return page_management.NewPostDashboardSetupNotFound().WithPayload(&models.GeneralResponse{
					Success: false,
					Error: &models.GeneralResponseError{
						Code:    404,
						Message: "Given account is not found in the database",
					},
					Message: "Account is not registered, please register as a super user..",
				})
			}
		}
		return page_management.NewPostDashboardSetupInternalServerError().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    500,
				Message: err.Error(),
			},
			Message: "Error occurred when trying to process the request",
		})
	}

	if superUser.Role != "super" {
		logger.Log.Info("user " + claims.Email + " is not a super user")
		return page_management.NewPostDashboardSetupForbidden().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    403,
				Message: "user " + claims.Email + " is not a super user",
			},
			Message: "Forbidden, Please login as super user to continue the request..",
		})
	}

	// Check parameters

	var userDetails *database.UserAuth
	if params.DashboardSetupRequest.UserType.(string) == "op" {
		userDetails, err = database.SelectOneUserByEmail(db, params.DashboardSetupRequest.UserRef.(string))
		if err != nil {
			logger.Log.Error(err.Error())
			if err == pg.ErrNoRows {
				return page_management.NewPostDashboardSetupNotFound().WithPayload(&models.GeneralResponse{
					Success: false,
					Error: &models.GeneralResponseError{
						Code:    404,
						Message: "No op user for given email \"" + params.DashboardSetupRequest.UserRef.(string) + "\" was found",
					},
					Message: "No user for given email \"" + params.DashboardSetupRequest.UserRef.(string) + "\" was found",
				})
			}
			return page_management.NewPostDashboardSetupInternalServerError().WithPayload(&models.GeneralResponse{
				Success: false,
				Error: &models.GeneralResponseError{
					Code:    500,
					Message: err.Error(),
				},
				Message: "Error occurred when trying to process the request",
			})
		}
	} else {
		userDetails, err = database.SelectOneUserByOAuthID(db, params.DashboardSetupRequest.UserRef.(string))
		if err != nil {
			logger.Log.Error(err.Error())
			if err == pg.ErrNoRows {
				return page_management.NewPostDashboardSetupNotFound().WithPayload(&models.GeneralResponse{
					Success: false,
					Error: &models.GeneralResponseError{
						Code:    404,
						Message: "No oauth user for given oauthid \"" + params.DashboardSetupRequest.UserRef.(string) + "\" was found",
					},
					Message: "No user for given oauthid \"" + params.DashboardSetupRequest.UserRef.(string) + "\" was found",
				})
			}
			return page_management.NewPostDashboardSetupInternalServerError().WithPayload(&models.GeneralResponse{
				Success: false,
				Error: &models.GeneralResponseError{
					Code:    500,
					Message: err.Error(),
				},
				Message: "Error occurred when trying to process the request",
			})
		}
	}

	userDetails.LogoURL = params.DashboardSetupRequest.LogoURL.(string)
	userDetails.Organization = params.DashboardSetupRequest.Organization.(string)
	userDetails.BackgroundColor = params.DashboardSetupRequest.BgColor.(string)
	userDetails.FontColor = params.DashboardSetupRequest.FontColor.(string)
	userDetails.NewsfeedBackgroundColor = params.DashboardSetupRequest.NewsfeedBGColor.(string)
	userDetails.NewsfeedFontColor = params.DashboardSetupRequest.NewseedFontColor.(string)

	err = database.UpdateUser(db, userDetails)
	if err != nil {
		logger.Log.Error(err.Error())
		return page_management.NewGetDashboardDetailsEmailTypeInternalServerError().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    500,
				Message: err.Error(),
			},
			Message: "Error occurred when trying to process the request",
		})
	}

	return page_management.NewPostDashboardSetupOK().WithPayload(&models.GeneralResponse{
		Success: true,
		Error:   nil,
		Message: "Newsfeed Setup Details successfully updated..",
	})
}
