package services

import (
	"github.com/Prashanth-GS/test-swagger/internal/logger"
	"golang.org/x/crypto/bcrypt"
)

// HashPassword Function
func HashPassword(password string) string {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		logger.Log.Error(err.Error())
	}
	return string(hash)
}

// CheckPassword Function
func CheckPassword(hashedPwd string, password string) bool {
	byteHash := []byte(hashedPwd)
	err := bcrypt.CompareHashAndPassword(byteHash, []byte(password))
	if err != nil {
		logger.Log.Error(err.Error())
		return false
	}
	return true
}
