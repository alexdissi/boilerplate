package domain

import "errors"

var (
	ErrInvalidUserName           = errors.New("name is required")
	ErrInvalidUserNameLength     = errors.New("name must be between 2 and 100 characters")
	ErrInvalidUserEmail          = errors.New("email is required")
	ErrInvalidUserEmailFormat    = errors.New("email format is invalid")
	ErrInvalidUserPassword       = errors.New("password is required")
	ErrUserNotFound              = errors.New("user not found")
	ErrInvalidUserPasswordFormat = errors.New("password must be at least 8 characters, contain uppercase, lowercase, number, and special character")
	ErrUserAlreadyExists         = errors.New("user with this email already exists")
	ErrInvalidCredentials        = errors.New("invalid email or password")
	ErrTooManyLoginAttempts      = errors.New("too many login attempts, please try again later")
	ErrSessionNotFound           = errors.New("session not found")
)
