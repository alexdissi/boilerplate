package domain

import "errors"

var (
	ErrUserNotFound  = errors.New("user not found")
	ErrInvalidUserID = errors.New("invalid user ID")
	ErrInvalidEmail  = errors.New("invalid email")
)
