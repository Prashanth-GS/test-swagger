package services

import (
	"strings"

	"github.com/Prashanth-GS/test-swagger/internal/database"
	"github.com/Prashanth-GS/test-swagger/internal/logger"
	"github.com/Prashanth-GS/test-swagger/models"
	"github.com/Prashanth-GS/test-swagger/restapi/operations/domain_management"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-pg/pg"
)

// HandleGetTLD Function
func HandleGetTLD(db *pg.DB, params *domain_management.GetToplevelDomainParams) middleware.Responder {
	logger.Log.Info("Get TopLevel Domains called..")

	authHeader := params.HTTPRequest.Header.Get("Authorization")
	logger.Log.Info(authHeader)
	if authHeader == "" {
		return domain_management.NewGetToplevelDomainBadRequest().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    400,
				Message: "Authorization Header not set",
			},
			Message: "Bad Request, Please try again later.",
		})
	}
	authBearerArray := strings.Split(authHeader, " ")
	if len(authBearerArray) < 2 {
		return domain_management.NewGetToplevelDomainUnauthorized().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    401,
				Message: "Token is Invalid",
			},
			Message: "Unauthorized, Please login to continue..",
		})
	}
	_, err := ValidateJWT(authBearerArray[1])
	if err != nil {
		logger.Log.Info(err.Error())
		if err == jwt.ErrSignatureInvalid {
			return domain_management.NewGetToplevelDomainUnauthorized().WithPayload(&models.GeneralResponse{
				Success: false,
				Error: &models.GeneralResponseError{
					Code:    401,
					Message: "Token is Invalid",
				},
				Message: "Unauthorized, Please login to continue..",
			})
		}
		return domain_management.NewGetToplevelDomainBadRequest().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    400,
				Message: "Token validation produced an error",
			},
			Message: "Bad Request, Please login to continue..",
		})
	}

	tlDomainsList, err := database.SelectAllDomains(db)
	if err != nil {
		logger.Log.Error(err.Error())
		if err == pg.ErrNoRows {
			return domain_management.NewGetToplevelDomainNotFound().WithPayload(&models.GeneralResponse{
				Success: false,
				Error: &models.GeneralResponseError{
					Code:    404,
					Message: "No toplevel domain data found",
				},
				Message: "No top level domain data found",
			})
		}
		return domain_management.NewGetToplevelDomainInternalServerError().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    500,
				Message: "Error while retrieving data",
			},
			Message: "Something went wrong, please try again later",
		})
	}

	var tlDomainsData []*models.AllTLDResponseDataItems0
	for _, tlDomainItem := range tlDomainsList {
		item := models.AllTLDResponseDataItems0{
			Owner:       tlDomainItem.Owner,
			Name:        tlDomainItem.Name,
			Description: tlDomainItem.Description,
		}
		tlDomainsData = append(tlDomainsData, &item)
	}

	return domain_management.NewGetToplevelDomainOK().WithPayload(&models.AllTLDResponse{
		Success: true,
		Error:   nil,
		Data:    tlDomainsData,
	})
}

// HandlePostTLD Function
func HandlePostTLD(db *pg.DB, params *domain_management.PostToplevelDomainParams) middleware.Responder {
	logger.Log.Info("Post TopLevel Domains called..")

	// Check for the access Toke and verify that it is valid and belongs to a super user
	authHeader := params.HTTPRequest.Header.Get("Authorization")
	logger.Log.Info(authHeader)
	authBearerArray := strings.Split(authHeader, " ")
	if len(authBearerArray) < 2 {
		return domain_management.NewPostToplevelDomainUnauthorized().WithPayload(&models.GeneralResponse{
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
			return domain_management.NewPostToplevelDomainUnauthorized().WithPayload(&models.GeneralResponse{
				Success: false,
				Error: &models.GeneralResponseError{
					Code:    401,
					Message: "Token is Invalid",
				},
				Message: "Unauthorized, Please login to continue..",
			})
		}
		return domain_management.NewPostToplevelDomainBadRequest().WithPayload(&models.GeneralResponse{
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
				return domain_management.NewPostToplevelDomainNotFound().WithPayload(&models.GeneralResponse{
					Success: false,
					Error: &models.GeneralResponseError{
						Code:    404,
						Message: "Given account is not found in the database",
					},
					Message: "Account is not registered, please register as a super user..",
				})
			}
		}
	}

	if superUser.Role != "super" {
		logger.Log.Info("user " + claims.Email + " is not a super user")
		return domain_management.NewPostToplevelDomainForbidden().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    403,
				Message: "user " + claims.Email + " is not a super user",
			},
			Message: "Forbidden, Please login as super user to continue the request..",
		})
	}

	if params.AddTLDRequest.Name == nil || params.AddTLDRequest.Name == "" ||
		params.AddTLDRequest.Owner == nil || params.AddTLDRequest.Owner == "" ||
		params.AddTLDRequest.Description == nil || params.AddTLDRequest.Description == "" {
		logger.Log.Error("BadRequest - Invalid parameters..")
		return domain_management.NewPostToplevelDomainBadRequest().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    400,
				Message: "Invalid Parameters",
			},
			Message: "Invalid parameters",
		})
	}

	tlDomain := database.ToplevelDomain{
		Name:        params.AddTLDRequest.Name.(string),
		Owner:       params.AddTLDRequest.Owner.(string),
		Description: params.AddTLDRequest.Description.(string),
	}
	err = database.AddNewToplevelDomain(db, &tlDomain)
	if err != nil {
		logger.Log.Error(err.Error())
		return domain_management.NewPostToplevelDomainInternalServerError().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    500,
				Message: err.Error(),
			},
			Message: "Error occurred when trying to process the request",
		})
	}

	logger.Log.Info("Toplevel Domain added to the database..")
	return domain_management.NewPostToplevelDomainOK().WithPayload(&models.GeneralResponse{
		Success: true,
		Error:   nil,
		Message: "Toplevel Domain added to the database..",
	})
}
