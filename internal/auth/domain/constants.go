package domain

import "regexp"

const (
	SessionDurationMinutes = 60 * 24 * 15

	MinNameLength            = 2
	MaxNameLength            = 100
	MinPasswordLength        = 8
	MaxLoginAttempts         = 5
	MaxForgotPasswordAttempts = 3
)

type OAuthProvider string

const (
	AuthProviderEmail  OAuthProvider = "EMAIL"
	AuthProviderGoogle OAuthProvider = "GOOGLE"
)

var (
	emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
)
