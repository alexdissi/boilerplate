package domain

import (
	"crypto/rand"
	"encoding/hex"

	"github.com/google/uuid"
)

type Session struct {
	ID           uuid.UUID
	UserID       uuid.UUID
	SessionToken string
	IpAddress    string
	UserAgent    string
	ExpiresAt    string
	CreatedAt    string
}

func GenerateSecureToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
