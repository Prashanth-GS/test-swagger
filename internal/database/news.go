package database

import (
	"strings"

	"github.com/Prashanth-GS/test-swagger/internal/logger"
	"github.com/go-pg/pg"
	"github.com/go-pg/pg/orm"
)

// News Model
type News struct {
	ID          int `sql:", pk"`
	ImageURL    string
	Healine     string
	Description string
}

// CreateNewsRelation Function
func CreateNewsRelation(db *pg.DB) error {
	logger.Log.Info("Trying to create NEWS Table..")
	tables := []interface{}{(*News)(nil)}
	for _, model := range tables {
		err := db.CreateTable(model, &orm.CreateTableOptions{
			Temp: false,
		})
		if err != nil {
			logger.Log.Error("Error:" + err.Error())
			if strings.Contains(err.Error(), "already exists") {
				logger.Log.Warn("Warning:" + err.Error())
			} else {
				return err
			}
		}
	}
	return nil
}

// SelectAllNews Function
func SelectAllNews(db *pg.DB) ([]News, error) {
	var news []News
	err := db.Model().Table("news").Select(&news)
	if err != nil {
		logger.Log.Error("Select error: " + err.Error())
		return nil, err
	}

	return news, nil
}
