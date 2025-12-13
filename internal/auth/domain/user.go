package domain

import (
	"regexp"

	"github.com/google/uuid"
)

var (
	emailRegex    = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	passwordRegex = regexp.MustCompile(`^[A-Za-z\d@$!%*?&]{8,}$`)
)

type UserAuth struct {
	ID             uuid.UUID
	Email          string
	PasswordHash   string
	FirstName      string
	LastName       string
	ProfilePicture string
	LastLoginAt    *string
	IsActive       bool
}

func (u *UserAuth) Validate() error {
	if u.Email == "" {
		return ErrInvalidUserEmail
	}

	if !emailRegex.MatchString(u.Email) {
		return ErrInvalidUserEmailFormat
	}

	if u.PasswordHash == "" {
		return ErrInvalidUserPassword
	}

	if u.FirstName == "" || u.LastName == "" {
		return ErrInvalidUserName
	}

	if len(u.FirstName) < 2 || len(u.FirstName) > 100 ||
		len(u.LastName) < 2 || len(u.LastName) > 100 {
		return ErrInvalidUserNameLength
	}

	return nil
}

func IsValidEmail(email string) bool {
	return emailRegex.MatchString(email)
}

func IsValidPassword(password string) bool {
	if !passwordRegex.MatchString(password) {
		return false
	}

	var (
		hasLower   = false
		hasUpper   = false
		hasDigit   = false
		hasSpecial = false
	)

	for _, char := range password {
		switch {
		case char >= 'a' && char <= 'z':
			hasLower = true
		case char >= 'A' && char <= 'Z':
			hasUpper = true
		case char >= '0' && char <= '9':
			hasDigit = true
		case char == '@' || char == '$' || char == '!' || char == '%' || char == '*' || char == '?' || char == '&':
			hasSpecial = true
		}
	}

	return hasLower && hasUpper && hasDigit && hasSpecial
}

func GenerateProfilePicture(firstName, lastName string) string {
	if len(firstName) == 0 || len(lastName) == 0 {
		return "https://api.dicebear.com/6.x/initials/svg?seed=JD"
	}

	initials := firstName[:1] + lastName[:1]
	return "https://api.dicebear.com/6.x/initials/svg?seed=" + initials
}
