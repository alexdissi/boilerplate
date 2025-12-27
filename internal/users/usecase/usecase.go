package usecase

import (
	"context"

	"mime/multipart"
)

//go:generate mockgen -destination=../test/mock_user_usecase.go -package=test my_project/internal/users/usecase UserUsecase
type UserUsecase interface {
	GetUserProfile(ctx context.Context, userID string) (UserProfileResponse, error)
	UpdateUserProfile(ctx context.Context, userID string, req UpdateUserRequest) (UserProfileResponse, error)
	ChangePassword(ctx context.Context, userID string, req ChangePasswordRequest) error
	DeleteUser(ctx context.Context, userID string) error
	UploadAvatar(ctx context.Context, userID string, fileHeader *multipart.FileHeader) (string, error)
}
