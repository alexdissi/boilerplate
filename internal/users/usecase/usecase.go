package usecase

import "context"

//go:generate mockgen -destination=../test/mock_user_usecase.go -package=test my_project/internal/users/usecase UserUsecase
type UserUsecase interface {
	GetUserProfile(ctx context.Context, userID string) (UserProfileResponse, error)
	UpdateUserProfile(ctx context.Context, userID string, req UpdateUserRequest) (UserProfileResponse, error)
}
