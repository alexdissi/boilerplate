package usecase

import (
	"my_project/internal/users/domain"
)

type UserProfileResponse struct {
	ID             string  `json:"id"`
	Email          string  `json:"email"`
	FirstName      string  `json:"first_name"`
	LastName       string  `json:"last_name"`
	ProfilePicture string  `json:"profile_picture"`
	LastLoginAt    *string `json:"last_login_at"`
	IsActive       bool    `json:"is_active"`
}

type UpdateUserRequest struct {
	Email         *string `json:"email,omitempty" form:"email" validate:"omitempty,email"`
	FirstName     *string `json:"first_name,omitempty" form:"first_name" validate:"omitempty,min=2,max=50"`
	LastName      *string `json:"last_name,omitempty" form:"last_name" validate:"omitempty,min=2,max=50"`
	ProfilePicture *string `json:"profile_picture,omitempty" form:"profile_picture"`
}

type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" form:"current_password" validate:"required,min=8"`
	NewPassword     string `json:"new_password" form:"new_password" validate:"required,min=8,max=128,strongpassword"`
}

func ToUserProfileResponse(user *domain.User) UserProfileResponse {
	var lastLoginAt *string
	if user.LastLoginAt != nil {
		lastLoginAtStr := user.LastLoginAt.Format("2006-01-02T15:04:05Z")
		lastLoginAt = &lastLoginAtStr
	}

	return UserProfileResponse{
		ID:             user.ID.String(),
		Email:          user.Email,
		FirstName:      user.FirstName,
		LastName:       user.LastName,
		ProfilePicture: user.ProfilePicture,
		LastLoginAt:    lastLoginAt,
		IsActive:       user.IsActive,
	}
}
