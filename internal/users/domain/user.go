package domain

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID             uuid.UUID  `json:"id"`
	Email          string     `json:"email"`
	FirstName      string     `json:"first_name"`
	LastName       string     `json:"last_name"`
	ProfilePicture string     `json:"profile_picture"`
	LastLoginAt    *time.Time `json:"last_login_at"`
	IsActive       bool       `json:"is_active"`
	PasswordHash   string     `json:"-"`
}
