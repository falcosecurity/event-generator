package validate

import (
	"github.com/go-playground/validator/v10"
	logger "github.com/sirupsen/logrus"
)

func isLogrusLevel(fl validator.FieldLevel) bool {
	level := fl.Field().String()
	_, err := logger.ParseLevel(level)
	if err != nil {
		return false
	}
	return true
}
