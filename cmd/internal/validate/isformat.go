package validate

import (
	"github.com/go-playground/validator/v10"
)

func isFormat(fl validator.FieldLevel) bool {
	switch fl.Field().String() {
	case "text":
		return true
	case "json":
		return true
	}

	return false
}
