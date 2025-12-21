package validator

import (
	"unicode"

	"github.com/go-playground/validator/v10"
)

// ValidateStrongPassword validates password strength requirements
func ValidateStrongPassword(fl validator.FieldLevel) bool {
	password := fl.Field().String()

	if len(password) < 8 || len(password) > 128 {
		return false
	}

	var (
		hasUpper   bool
		hasLower   bool
		hasNumber  bool
		hasSpecial bool
	)

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	return hasUpper && hasLower && hasNumber && hasSpecial
}

func RegisterPasswordValidation(v *validator.Validate) {
	v.RegisterValidation("strongpassword", ValidateStrongPassword)
}
