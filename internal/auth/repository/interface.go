package repository

import (
	"context"
	"my_project/internal/auth/domain"
	"time"

	"github.com/google/uuid"
)

//go:generate mockgen -destination=../test/mock_user_repository.go -package=test my_project/internal/auth/repository UserRepository
type UserRepository interface {
	CreateUser(ctx context.Context, user *domain.UserAuth) (*domain.UserAuth, error)
	UserExistsByEmail(ctx context.Context, email string) (bool, error)
	GetUserByEmail(ctx context.Context, email string) (*domain.UserAuth, error)
	GetUserByID(ctx context.Context, userID uuid.UUID) (*domain.UserAuth, error)
	CreateSession(ctx context.Context, session *domain.Session) error
	DeleteSessionByToken(ctx context.Context, token string) error
	GetSessionByToken(ctx context.Context, token string) (*domain.Session, error)
	GetUserByGoogleID(ctx context.Context, googleID string) (*domain.UserAuth, error)
	UpdateGoogleOAuth(ctx context.Context, userID uuid.UUID, googleID string, provider domain.OAuthProvider) error
	SetResetPasswordToken(ctx context.Context, email, token string, expiresAt time.Time) error
	GetUserByResetToken(ctx context.Context, token string) (*domain.UserAuth, error)
	ResetPassword(ctx context.Context, userID uuid.UUID, newPasswordHash string) error
	UpdateLastLoginAt(ctx context.Context, userID uuid.UUID) error
	CreateSubscription(ctx context.Context, subscription *domain.AuthSubscription) error
}
