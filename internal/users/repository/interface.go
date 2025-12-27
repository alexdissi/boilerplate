package repository

import (
	"context"

	"my_project/internal/users/domain"

	"github.com/google/uuid"
)

//go:generate mockgen -destination=../test/mock_user_repository.go -package=test my_project/internal/users/repository UserRepository
type UserRepository interface {
	GetUserByID(ctx context.Context, userID uuid.UUID) (*domain.User, error)
	UpdateUser(ctx context.Context, user *domain.User) (*domain.User, error)
	UpdatePassword(ctx context.Context, userID uuid.UUID, passwordHash string) error
	DeleteUser(ctx context.Context, userID uuid.UUID) error
}
