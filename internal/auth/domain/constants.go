package domain

import "regexp"

const (
	SessionDurationMinutes = 60 * 24 * 15

	MinNameLength     = 2
	MaxNameLength     = 100
	MinPasswordLength = 8
	MaxLoginAttempts  = 5
)

type OAuthProvider string

const (
	AuthProviderEmail  OAuthProvider = "email"
	AuthProviderGoogle OAuthProvider = "google"
)

var (
	emailRegex           = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	passwordHasLowercase = regexp.MustCompile(`[a-z]`)
	passwordHasUppercase = regexp.MustCompile(`[A-Z]`)
	passwordHasDigit     = regexp.MustCompile(`\d`)
	passwordHasSpecial   = regexp.MustCompile(`[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]`)
)
