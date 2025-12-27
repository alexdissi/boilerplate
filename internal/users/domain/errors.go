package domain

import "errors"

var (
	ErrUserNotFound              = errors.New("user not found")
	ErrInvalidUserID             = errors.New("invalid user ID")
	ErrInvalidEmail              = errors.New("invalid email")
	ErrInvalidCurrentPassword    = errors.New("current password is incorrect")
	ErrPasswordVerificationFailed = errors.New("password verification failed")
	ErrPasswordProcessingFailed  = errors.New("failed to process new password")
	ErrUserUpdateFailed          = errors.New("failed to update user")
	ErrInvalidFileFormat         = errors.New("invalid file format")
)
