package services

import (
	"github.com/Prashanth-GS/test-swagger/internal/database"
	"github.com/Prashanth-GS/test-swagger/internal/logger"
	"github.com/Prashanth-GS/test-swagger/models"
	"github.com/Prashanth-GS/test-swagger/restapi/operations/news"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-pg/pg"
)

// HandleGetAllNews Function
func HandleGetAllNews(db *pg.DB, params *news.GetNewsParams) middleware.Responder {
	logger.Log.Info("Get All News called..")

	// authHeader := params.HTTPRequest.Header.Get("Authorization")
	// logger.Log.Info(authHeader)
	// if authHeader == "" {
	// 	return news.NewGetNewsBadRequest().WithPayload(&models.GeneralResponse{
	// 		Success: false,
	// 		Error: &models.GeneralResponseError{
	// 			Code:    400,
	// 			Message: "Authorization Header not set",
	// 		},
	// 		Message: "Bad Request, Please try again later.",
	// 	})
	// }
	// _, err := ValidateJWT(strings.Split(authHeader, " ")[1])
	// if err != nil {
	// 	logger.Log.Info(err.Error())
	// 	if err == jwt.ErrSignatureInvalid {
	// 		return news.NewGetNewsUnauthorized().WithPayload(&models.GeneralResponse{
	// 			Success: false,
	// 			Error: &models.GeneralResponseError{
	// 				Code:    401,
	// 				Message: "Token is Invalid",
	// 			},
	// 			Message: "Unauthorized, Please login to continue..",
	// 		})
	// 	}
	// 	return news.NewGetNewsBadRequest().WithPayload(&models.GeneralResponse{
	// 		Success: false,
	// 		Error: &models.GeneralResponseError{
	// 			Code:    400,
	// 			Message: "Token validation produced an error",
	// 		},
	// 		Message: "Bad Request, Please login to continue..",
	// 	})
	// }

	newsList, err := database.SelectAllNews(db)
	if err != nil {
		logger.Log.Error(err.Error())
		if err == pg.ErrNoRows {
			return news.NewGetNewsNotFound().WithPayload(&models.GeneralResponse{
				Success: false,
				Error: &models.GeneralResponseError{
					Code:    404,
					Message: "No news data found",
				},
				Message: "No news data found",
			})
		}
		return news.NewGetNewsInternalServerError().WithPayload(&models.GeneralResponse{
			Success: false,
			Error: &models.GeneralResponseError{
				Code:    500,
				Message: "Error while retrieving data",
			},
			Message: "Something went wrong, please try again later",
		})
	}

	var newsData []*models.AllNewsResponseDataItems0
	for _, newsItem := range newsList {
		item := models.AllNewsResponseDataItems0{
			ImageURL:    newsItem.ImageURL,
			Headline:    newsItem.Healine,
			Description: newsItem.Description,
		}
		newsData = append(newsData, &item)
	}

	return news.NewGetNewsOK().WithPayload(&models.AllNewsResponse{
		Success: true,
		Error:   nil,
		Data:    newsData,
	})
}

// HandleAddNews Function
func HandleAddNews() {
	logger.Log.Info("Add news called..")
}
