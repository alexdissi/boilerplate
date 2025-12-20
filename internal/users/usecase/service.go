package usecase

import (
	"context"
	"errors"

	"my_project/internal/users/domain"
	"my_project/internal/users/repository"
	"my_project/pkg/logger"

	"github.com/google/uuid"
)

type userUsecase struct {
	userRepo repository.UserRepository
}

func NewUserUsecase(userRepo repository.UserRepository) UserUsecase {
	return &userUsecase{
		userRepo: userRepo,
	}
}

func (u *userUsecase) GetUserProfile(ctx context.Context, userID string) (UserProfileResponse, error) {
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return UserProfileResponse{}, domain.ErrInvalidUserID
	}

	user, err := u.userRepo.GetUserByID(ctx, userUUID)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			logger.Error("user not found", err)
			return UserProfileResponse{}, domain.ErrUserNotFound
		}
		return UserProfileResponse{}, err
	}

	return ToUserProfileResponse(user), nil
}

func (u *userUsecase) UpdateUserProfile(ctx context.Context, userID string, req UpdateUserRequest) (UserProfileResponse, error) {
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return UserProfileResponse{}, domain.ErrInvalidUserID
	}

	user, err := u.userRepo.GetUserByID(ctx, userUUID)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			logger.Error("user not found", err)
			return UserProfileResponse{}, domain.ErrUserNotFound
		}
		return UserProfileResponse{}, err
	}

	if req.Email != nil {
		user.Email = *req.Email
	}
	if req.FirstName != nil {
		user.FirstName = *req.FirstName
	}
	if req.LastName != nil {
		user.LastName = *req.LastName
	}

	updatedUser, err := u.userRepo.UpdateUser(ctx, user)
	if err != nil {
		logger.Error("failed to update user", err)
		return UserProfileResponse{}, err
	}

	return ToUserProfileResponse(updatedUser), nil
}
