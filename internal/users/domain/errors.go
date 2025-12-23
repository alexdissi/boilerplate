package domain

import "errors"

var (
	ErrUserNotFound                = errors.New("user not found")
	ErrInvalidUserID               = errors.New("invalid user ID")
	ErrInvalidEmail                = errors.New("invalid email")
	ErrInvalidCurrentPassword      = errors.New("current password is incorrect")
	ErrPasswordVerificationFailed  = errors.New("password verification failed")
	ErrPasswordProcessingFailed   = errors.New("failed to process new password")
	ErrUserUpdateFailed            = errors.New("failed to update user")
	ErrTwoFactorAlreadyEnabled     = errors.New("two-factor authentication already enabled")
	ErrTwoFactorNotEnabled         = errors.New("two-factor authentication not enabled")
	ErrInvalidTwoFactorCode        = errors.New("invalid two-factor code")
	ErrFailedToGenerateTwoFactor   = errors.New("failed to generate two-factor secret")
	ErrFailedToEnableTwoFactor     = errors.New("failed to enable two-factor authentication")
	ErrFailedToDisableTwoFactor    = errors.New("failed to disable two-factor authentication")
	ErrInvalidFileFormat         = errors.New("invalid file format")
)
