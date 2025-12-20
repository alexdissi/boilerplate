package usecase

import "context"

type UserUsecase interface {
	GetUserProfile(ctx context.Context, userID string) (UserProfileResponse, error)
}
