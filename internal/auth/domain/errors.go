package domain

import "errors"

var (
	ErrInvalidUserName               = errors.New("name is required")
	ErrInvalidUserNameLength         = errors.New("name must be between 2 and 100 characters")
	ErrInvalidUserEmail              = errors.New("email is required")
	ErrInvalidUserEmailFormat        = errors.New("email format is invalid")
	ErrInvalidUserPassword           = errors.New("password is required")
	ErrUserNotFound                  = errors.New("user not found")
	ErrInvalidUserPasswordFormat     = errors.New("password must be at least 8 characters, contain uppercase, lowercase, number, and special character")
	ErrUserAlreadyExists             = errors.New("user with this email already exists")
	ErrInvalidCredentials            = errors.New("invalid email or password")
	ErrTooManyLoginAttempts          = errors.New("too many login attempts, please try again later")
	ErrTooManyForgotPasswordAttempts = errors.New("too many password reset requests, please try again later")
	ErrSessionNotFound               = errors.New("session not found")
	ErrOAuthTokenInvalid             = errors.New("invalid OAuth token")
	ErrOAuthUserNotFound             = errors.New("user not found with OAuth provider")
	ErrOAuthEmailRequired            = errors.New("email is required from OAuth provider")
	ErrOAuthAccountLinkingRequired   = errors.New("account linking confirmation required")
	ErrTwoFactorNotEnabled           = errors.New("two-factor authentication is not enabled")
	ErrInvalidTwoFactorCode          = errors.New("invalid two-factor code")
)
