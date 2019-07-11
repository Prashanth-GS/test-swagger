package services

import (
	"reflect"
	"strings"

	"github.com/Prashanth-GS/test-swagger/internal/database"
	"github.com/Prashanth-GS/test-swagger/internal/logger"
	"github.com/Prashanth-GS/test-swagger/models"
	"github.com/Prashanth-GS/test-swagger/restapi/operations/users_management"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-pg/pg"
)

// HandleGetAllUsers Function
func HandleGetAllUsers(db *pg.DB, params *users_management.GetUsersParams) middleware.Responder {
	logger.Log.Info("Get all users called..")

	// Check for the access Toke and verify that it is valid and belongs to a super user
	authHeader := params.HTTPRequest.Header.Get("Authorization")
	logger.Log.Info(authHeader)
	authBearerArray := strings.Split(authHeader, " ")
	if len(authBearerArray) < 2 {
		return users_management.NewGetUsersUnauthorized().WithPayload(&models.GeneralResponse{
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
			return users_management.NewGetUsersUnauthorized().WithPayload(&models.GeneralResponse{
				Success: false,
				Error: &models.GeneralResponseError{
					Code:    401,
					Message: "Token is Invalid",
				},
				Message: "Unauthorized, Please login to continue..",
			})
		}
		return users_management.NewGetUsersBadRequest().WithPayload(&models.GeneralResponse{
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
				return users_management.NewGetUsersNotFound().WithPayload(&models.GeneralResponse{
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
		return users_management.NewGetUsersForbidden().WithPayload(&models.GeneralResponse{
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
			return users_management.NewGetUsersNotFound().WithPayload(&models.GeneralResponse{
				Success: false,
				Error: &models.GeneralResponseError{
					Code:    404,
					Message: "No news data found",
				},
				Message: "No news data found",
			})
		}
		return users_management.NewGetUsersInternalServerError().WithPayload(&models.GeneralResponse{
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
			Name:              UserItem.Name,
			Mode:              UserItem.Mode,
			Role:              UserItem.Role,
			Locked:            UserItem.Locked,
			Organization:      UserItem.Organization,
			ToplevelDomain:    UserItem.ToplevelDomain,
			LogoURL:           UserItem.LogoURL,
			BgColor:           UserItem.BackgroundColor,
			FontColor:         UserItem.FontColor,
			NewsfeedBGColor:   UserItem.NewsfeedBackgroundColor,
			NewsfeedFontColor: UserItem.NewsfeedFontColor,
		}
		if UserItem.Mode == "op" {
			item.Ref = UserItem.Email
		} else {
			item.Ref = UserItem.OAuthID
		}
		usersData = append(usersData, &item)
	}

	return users_management.NewGetUsersOK().WithPayload(&models.AllUsersResponse{
		Success: true,
		Error:   nil,
		Data:    usersData,
	})
}

// HandleLockUser Function
func HandleLockUser(db *pg.DB, params *users_management.PostLockUserParams) middleware.Responder {
	logger.Log.Info("Lock User called..")

	// Check for the access Toke and verify that it is valid and belongs to a super user
	authHeader := params.HTTPRequest.Header.Get("Authorization")
	logger.Log.Info(authHeader)
	authBearerArray := strings.Split(authHeader, " ")
	if len(authBearerArray) < 2 {
		return users_management.NewPostLockUserUnauthorized().WithPayload(&models.GeneralResponse{
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
			return users_management.NewPostLockUserUnauthorized().WithPayload(&models.GeneralResponse{
				Success: false,
				Error: &models.GeneralResponseError{
					Code:    401,
					Message: "Token is Invalid",
				},
				Message: "Unauthorized, Please login to continue..",
			})
		}
		return users_management.NewPostLockUserBadRequest().WithPayload(&models.GeneralResponse{
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
				return users_management.NewPostLockUserNotFound().WithPayload(&models.GeneralResponse{
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
		return users_management.NewPostLockUserForbidden().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    403,
				Message: "user " + claims.Email + " is not a super user",
			},
			Message: "Forbidden, Please login as super user to continue the request..",
		})
	}

	if params.LockUserRequest.Mode == nil || params.LockUserRequest.Mode == "" ||
		params.LockUserRequest.Cred == nil || params.LockUserRequest.Cred == "" ||
		params.LockUserRequest.Lock == nil || reflect.TypeOf(params.LockUserRequest.Lock).Kind() != reflect.Bool {
		logger.Log.Error("BadRequest - Invalid parameters..")
		return users_management.NewPostLockUserBadRequest().WithPayload(&models.GeneralResponse{
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
					return users_management.NewPostLockUserNotFound().WithPayload(&models.GeneralResponse{
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
		return users_management.NewPostLockUserInternalServerError().WithPayload(&models.GeneralResponse{
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

		return users_management.NewPostLockUserOK().WithPayload(&models.GeneralResponse{
			Success: true,
			Error:   nil,
			Message: "User successfully locked.",
		})
	}
	logger.Log.Info("User " + params.LockUserRequest.Cred.(string) + " unlocked")

	return users_management.NewPostLockUserOK().WithPayload(&models.GeneralResponse{
		Success: true,
		Error:   nil,
		Message: "User successfully unlocked.",
	})
}
