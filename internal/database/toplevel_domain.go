package database

import (
	"strings"

	"github.com/Prashanth-GS/test-swagger/internal/logger"
	"github.com/go-pg/pg"
	"github.com/go-pg/pg/orm"
)

// ToplevelDomain Model
type ToplevelDomain struct {
	ID          int `sql:", pk"`
	Name        string
	Owner       string
	Description string
}

// CreateTLDomainsRelation Function
func CreateTLDomainsRelation(db *pg.DB) error {
	logger.Log.Info("Trying to create ToplevelDomains Table..")
	tables := []interface{}{(*ToplevelDomain)(nil)}
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

// SelectAllDomains Function
func SelectAllDomains(db *pg.DB) ([]ToplevelDomain, error) {
	var tlDomain []ToplevelDomain
	err := db.Model().Table("toplevel_domains").Select(&tlDomain)
	if err != nil {
		logger.Log.Error("Select error: " + err.Error())
		return nil, err
	}

	return tlDomain, nil
}

// AddNewToplevelDomain Function
func AddNewToplevelDomain(db *pg.DB, tld *ToplevelDomain) error {
	if err := db.Insert(tld); err != nil {
		logger.Log.Error("Insert Error: " + err.Error())
		return err
	}
	logger.Log.Info("ToplevelDomain added..")
	return nil
}
