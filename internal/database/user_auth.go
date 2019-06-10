package database

import (
	"strings"

	"github.com/Prashanth-GS/test-swagger/internal/logger"
	"github.com/go-pg/pg"
	"github.com/go-pg/pg/orm"
)

// UserAuth Model
type UserAuth struct {
	Email                string `sql:", pk"`
	Password             string
	Role                 string
	Organization         string
	EmployeeCount        int
	Designation          string
	ConfirmationAccepted bool `sql:"default: false"`
	DetailsRegistered    bool `sql:"default: false"`
}

// CreateUserAuthSchema Function
func CreateUserAuthSchema(db *pg.DB) error {
	tables := []interface{}{(*UserAuth)(nil)}
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

// SelectAllUsers Function
func SelectAllUsers(db *pg.DB) error {
	var users []UserAuth
	err := db.Model().Table("user_auth").Select(&users)
	if err != nil {
		logger.Log.Error("Select error: " + err.Error())
		return err
	}

	return nil
}

// SelectOneUser Function
func SelectOneUser(db *pg.DB, email string) (*UserAuth, error) {
	user := &UserAuth{Email: email}
	err := db.Select(user)
	if err != nil {
		logger.Log.Error("Select error: " + err.Error())
		return user, err
	}

	return user, nil
}

// AddNewUser Function
func AddNewUser(db *pg.DB, user *UserAuth) error {
	if err := db.Insert(user); err != nil {
		logger.Log.Error("Insert Error: " + err.Error())
		return err
	}
	logger.Log.Info("User added..")
	return nil
}

// UpdateUser Function
func UpdateUser(db *pg.DB, modifiedUser *UserAuth) error {
	err := db.Update(modifiedUser)
	if err != nil {
		logger.Log.Error("Update error: " + err.Error())
		return err
	}
	logger.Log.Info("User updated..")
	return nil
}

// DeleteUser Function
func DeleteUser(db *pg.DB, email string) error {
	user := &UserAuth{Email: email}
	err := db.Delete(user)
	if err != nil {
		logger.Log.Error("Delete error: " + err.Error())
		return err
	}
	logger.Log.Info("User deleted..")
	return nil
}