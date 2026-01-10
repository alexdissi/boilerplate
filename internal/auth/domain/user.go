package domain

import (
	"strings"
	"time"

	"github.com/google/uuid"
)

type UserAuth struct {
	ID               uuid.UUID
	Email            string
	PasswordHash     string
	FirstName        string
	LastName         string
	ProfilePicture   string
	LastLoginAt      *time.Time
	IsActive         bool
	GoogleID         string
	OAuthProvider    OAuthProvider
	TwoFactorEnabled bool
}

type AuthSubscription struct {
	UserID string
}

func (u *UserAuth) Validate() error {
	if u.Email == "" {
		return ErrInvalidUserEmail
	}

	u.Email = strings.TrimSpace(strings.ToLower(u.Email))
	if !emailRegex.MatchString(u.Email) {
		return ErrInvalidUserEmailFormat
	}

	if u.OAuthProvider == AuthProviderEmail && u.PasswordHash == "" {
		return ErrInvalidUserPassword
	}

	u.FirstName = strings.TrimSpace(u.FirstName)
	u.LastName = strings.TrimSpace(u.LastName)

	if u.FirstName == "" || u.LastName == "" {
		return ErrInvalidUserName
	}

	if len(u.FirstName) < MinNameLength || len(u.FirstName) > MaxNameLength ||
		len(u.LastName) < MinNameLength || len(u.LastName) > MaxNameLength {
		return ErrInvalidUserNameLength
	}

	return nil
}

func IsValidEmail(email string) bool {
	return emailRegex.MatchString(email)
}

func GenerateProfilePicture(firstName, lastName string) string {
	if len(firstName) == 0 || len(lastName) == 0 {
		return "https://api.dicebear.com/6.x/initials/svg?seed=JD"
	}

	initials := firstName[:1] + lastName[:1]
	return "https://api.dicebear.com/6.x/initials/svg?seed=" + initials
}
