package domain

import (
	"time"

	"github.com/google/uuid"
)

type UserTwoFactor struct {
	UserID           uuid.UUID
	EncryptedSecret  string
	BackupCodesCount int
	CodeHashes       []string
	EnabledAt        *time.Time
	CreatedAt        time.Time
	UpdatedAt        time.Time
}
