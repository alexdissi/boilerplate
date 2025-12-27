package usecase

import (
	"context"
	"errors"

	"my_project/internal/users/domain"
	"my_project/internal/users/repository"
	"my_project/pkg/logger"
	"my_project/pkg/password"

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

func (u *userUsecase) ChangePassword(ctx context.Context, userID string, req ChangePasswordRequest) error {
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return domain.ErrInvalidUserID
	}

	user, err := u.userRepo.GetUserByID(ctx, userUUID)
	if err != nil {
		logger.Error("failed to get user for password change", err)
		if errors.Is(err, domain.ErrUserNotFound) {
			return domain.ErrUserNotFound
		}
		return err
	}

	passwordMatch, err := password.ComparePassword(user.PasswordHash, req.CurrentPassword)
	if err != nil {
		logger.Error("password comparison error", err)
		return domain.ErrPasswordVerificationFailed
	}

	if !passwordMatch {
		return domain.ErrInvalidCurrentPassword
	}

	hashedPassword, err := password.HashPassword(req.NewPassword)
	if err != nil {
		logger.Error("failed to hash new password", err)
		return domain.ErrPasswordProcessingFailed
	}

	err = u.userRepo.UpdatePassword(ctx, userUUID, hashedPassword)
	if err != nil {
		logger.Error("failed to update password", err)
		return domain.ErrUserUpdateFailed
	}

	return nil
}

func (u *userUsecase) DeleteUser(ctx context.Context, userID string) error {
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return domain.ErrInvalidUserID
	}

	err = u.userRepo.DeleteUser(ctx, userUUID)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			logger.Error("user not found", err)
			return domain.ErrUserNotFound
		}
		logger.Error("failed to delete user", err)
		return err
	}

	return nil
}
