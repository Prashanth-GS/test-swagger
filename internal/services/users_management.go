package services

import (
	"strings"

	"github.com/Prashanth-GS/test-swagger/internal/database"
	"github.com/Prashanth-GS/test-swagger/internal/logger"
	"github.com/Prashanth-GS/test-swagger/models"
	"github.com/Prashanth-GS/test-swagger/restapi/operations/login"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-pg/pg"
)

// HandleGetAllUsers Function
func HandleGetAllUsers(db *pg.DB, params *login.GetUsersParams) middleware.Responder {
	logger.Log.Info("Get all users called..")

	// Check for the access Toke and verify that it is valid and belongs to a super user
	authHeader := params.HTTPRequest.Header.Get("Authorization")
	logger.Log.Info(authHeader)
	claims, err := ValidateJWT(strings.Split(authHeader, " ")[1])
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			return login.NewGetUsersUnauthorized().WithPayload(&models.GeneralResponse{
				Success: false,
				Error: &models.GeneralResponseError{
					Code:    401,
					Message: "Token is Invalid",
				},
				Message: "Unauthorized, Please reregister to continue..",
			})
		}
		return login.NewGetUsersBadRequest().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    400,
				Message: "Token validation produced an error",
			},
			Message: "Bad Request, Please reregister to continue..",
		})
	}

	superUser, err := database.SelectOneUserByEmail(db, claims.Email)
	if err != nil {
		logger.Log.Error(err.Error())
		if err == pg.ErrNoRows {
			if err == pg.ErrNoRows {
				return login.NewGetUsersNotFound().WithPayload(&models.GeneralResponse{
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
		return login.NewGetUsersForbidden().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    403,
				Message: "user " + claims.Email + " is not a super user",
			},
			Message: "Forbidden, Please login as super user to continue the request..",
		})
	}

	usersList, err := database.SelectAllUsers(db)
	if err != nil {
		logger.Log.Error(err.Error())
		if err == pg.ErrNoRows {
			return login.NewGetUsersNotFound().WithPayload(&models.GeneralResponse{
				Success: false,
				Error: &models.GeneralResponseError{
					Code:    404,
					Message: "No news data found",
				},
				Message: "No news data found",
			})
		}
		return login.NewGetUsersInternalServerError().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    500,
				Message: err.Error(),
			},
			Message: "Error occurred when trying to process the request",
		})
	}

	var usersData []*models.AllUsersResponseDataItems0
	for _, UserItem := range usersList {
		item := models.AllUsersResponseDataItems0{
			Name:   UserItem.Name,
			Mode:   UserItem.Mode,
			Role:   UserItem.Role,
			Locked: UserItem.Locked,
		}
		if UserItem.Mode == "op" {
			item.Ref = UserItem.Email
		} else {
			item.Ref = UserItem.OAuthID
		}
		usersData = append(usersData, &item)
	}

	return login.NewGetUsersOK().WithPayload(&models.AllUsersResponse{
		Success: true,
		Error:   nil,
		Data:    usersData,
	})
}

// HandleLockUser Function
func HandleLockUser(db *pg.DB, params *login.PostLockUserParams) middleware.Responder {
	logger.Log.Info("Lock User called..")

	// Check for the access Toke and verify that it is valid and belongs to a super user
	authHeader := params.HTTPRequest.Header.Get("Authorization")
	logger.Log.Info(authHeader)
	claims, err := ValidateJWT(strings.Split(authHeader, " ")[1])
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			return login.NewPostLockUserUnauthorized().WithPayload(&models.GeneralResponse{
				Success: false,
				Error: &models.GeneralResponseError{
					Code:    401,
					Message: "Token is Invalid",
				},
				Message: "Unauthorized, Please reregister to continue..",
			})
		}
		return login.NewPostLockUserBadRequest().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    400,
				Message: "Token validation produced an error",
			},
			Message: "Bad Request, Please reregister to continue..",
		})
	}

	superUser, err := database.SelectOneUserByEmail(db, claims.Email)
	if err != nil {
		logger.Log.Error(err.Error())
		if err == pg.ErrNoRows {
			if err == pg.ErrNoRows {
				return login.NewPostLockUserNotFound().WithPayload(&models.GeneralResponse{
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
		return login.NewPostLockUserForbidden().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    403,
				Message: "user " + claims.Email + " is not a super user",
			},
			Message: "Forbidden, Please login as super user to continue the request..",
		})
	}

	if params.LockUserRequest.Mode == nil || params.LockUserRequest.Mode == "" ||
		params.LockUserRequest.Cred == nil || params.LockUserRequest.Cred == "" || params.LockUserRequest.Lock == nil {
		logger.Log.Error("BadRequest - Invalid parameters..")
		return login.NewPostLockUserBadRequest().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    400,
				Message: "Invalid Parameters",
			},
			Message: "Invalid parameters",
		})
	}
	user, err := database.SelectOneUserByEmail(db, params.LockUserRequest.Cred.(string))
	if err != nil {
		logger.Log.Error(err.Error())
		if err == pg.ErrNoRows {
			user, err = database.SelectOneUserByOAuthID(db, params.LockUserRequest.Cred.(string))
			if err != nil {
				logger.Log.Error(err.Error())
				if err == pg.ErrNoRows {
					return login.NewPostLockUserNotFound().WithPayload(&models.GeneralResponse{
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

	if params.LockUserRequest.Lock.(bool) {
		user.Locked = true
	} else {
		user.Locked = false
	}
	err = database.UpdateUser(db, user)
	if err != nil {
		logger.Log.Error(err.Error())
		return login.NewPostLockUserInternalServerError().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    500,
				Message: err.Error(),
			},
			Message: "Error occurred when trying to process the request",
		})
	}

	if params.LockUserRequest.Lock.(bool) {
		logger.Log.Info("User " + params.LockUserRequest.Cred.(string) + " locked")

		return login.NewPostLockUserOK().WithPayload(&models.GeneralResponse{
			Success: true,
			Error:   nil,
			Message: "User successfully locked.",
		})
	}
	logger.Log.Info("User " + params.LockUserRequest.Cred.(string) + " unlocked")

	return login.NewPostLockUserOK().WithPayload(&models.GeneralResponse{
		Success: true,
		Error:   nil,
		Message: "User successfully unlocked.",
	})
}
