package test

import (
	"context"
	"testing"

	"my_project/internal/auth/domain"
	"my_project/internal/auth/usecase"
	"my_project/pkg/logger"
	"my_project/pkg/password"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func init() {
	logger.Init()
}

func setupService(t *testing.T) (*MockUserRepository, usecase.UserUsecase) {
	ctrl := gomock.NewController(t)
	mockRepo := NewMockUserRepository(ctrl)
	service := usecase.NewUserService(mockRepo)
	return mockRepo, service
}

func TestRegisterUser_Success(t *testing.T) {
	mockRepo, service := setupService(t)
	defer mockRepo.ctrl.Finish()

	ctx := context.Background()
	input := usecase.RegisterUserInput{
		FirstName: "John",
		LastName:  "Doe",
		Email:     "john.doe@example.com",
		Password:  "Password123!",
	}

	userID := uuid.New()

	mockRepo.EXPECT().
		UserExistsByEmail(ctx, input.Email).
		Return(false, nil)

	mockRepo.EXPECT().
		CreateUser(ctx, gomock.Any()).
		DoAndReturn(func(_ context.Context, user *domain.UserAuth) (*domain.UserAuth, error) {
			user.ID = userID
			return user, nil
		})

	result, err := service.RegisterUser(ctx, input)

	require.NoError(t, err)
	assert.Equal(t, userID.String(), result.ID)
	assert.Equal(t, input.Email, result.Email)
	assert.Equal(t, "User created successfully", result.Message)
}

func TestRegisterUser_InvalidPassword(t *testing.T) {
	_, service := setupService(t)

	ctx := context.Background()
	input := usecase.RegisterUserInput{
		FirstName: "John",
		LastName:  "Doe",
		Email:     "john.doe@example.com",
		Password:  "weak",
	}

	result, err := service.RegisterUser(ctx, input)

	assert.Error(t, err)
	assert.Equal(t, domain.ErrInvalidUserPasswordFormat, err)
	assert.Empty(t, result.ID)
}

func TestRegisterUser_UserAlreadyExists(t *testing.T) {
	mockRepo, service := setupService(t)
	defer mockRepo.ctrl.Finish()

	ctx := context.Background()
	input := usecase.RegisterUserInput{
		FirstName: "John",
		LastName:  "Doe",
		Email:     "john.doe@example.com",
		Password:  "Password123!",
	}

	mockRepo.EXPECT().
		UserExistsByEmail(ctx, input.Email).
		Return(true, nil)

	result, err := service.RegisterUser(ctx, input)

	assert.Error(t, err)
	assert.Equal(t, domain.ErrUserAlreadyExists, err)
	assert.Empty(t, result.ID)
}

func TestRegisterUser_InvalidEmail(t *testing.T) {
	mockRepo, service := setupService(t)
	defer mockRepo.ctrl.Finish()

	ctx := context.Background()
	input := usecase.RegisterUserInput{
		FirstName: "John",
		LastName:  "Doe",
		Email:     "invalid-email",
		Password:  "Password123!",
	}

	mockRepo.EXPECT().
		UserExistsByEmail(ctx, input.Email).
		Return(false, nil)

	result, err := service.RegisterUser(ctx, input)

	assert.Error(t, err)
	assert.Equal(t, domain.ErrInvalidUserEmailFormat, err)
	assert.Empty(t, result.ID)
}

// Login Tests

func TestLoginUser_Success(t *testing.T) {
	mockRepo, service := setupService(t)
	defer mockRepo.ctrl.Finish()

	ctx := context.Background()
	userAgent := "Mozilla/5.0"
	ipAddress := "192.168.1.1"

	userPassword := "Password123!"
	hashedPassword, err := password.HashPassword(userPassword)
	require.NoError(t, err)

	userID := uuid.New()
	existingUser := &domain.UserAuth{
		ID:           userID,
		Email:        "john.doe@example.com",
		PasswordHash: hashedPassword,
		FirstName:    "John",
		LastName:     "Doe",
		IsActive:     true,
	}

	input := usecase.LoginUserInput{
		Email:    "john.doe@example.com",
		Password: userPassword,
	}

	mockRepo.EXPECT().
		GetUserByEmail(ctx, input.Email).
		Return(existingUser, nil)

	mockRepo.EXPECT().
		CreateSession(ctx, gomock.Any()).
		DoAndReturn(func(_ context.Context, session *domain.Session) error {
			assert.Equal(t, userID, session.UserID)
			assert.Equal(t, ipAddress, session.IpAddress)
			assert.Equal(t, userAgent, session.UserAgent)
			assert.NotEmpty(t, session.SessionToken)
			return nil
		})

	result, err := service.LoginUser(ctx, input, userAgent, ipAddress)

	require.NoError(t, err)
	assert.Equal(t, existingUser.ID.String(), result.User.ID)
	assert.Equal(t, existingUser.Email, result.User.Email)
	assert.Equal(t, existingUser.FirstName, result.User.FirstName)
	assert.Equal(t, existingUser.LastName, result.User.LastName)
	assert.NotEmpty(t, result.Session.Token)
	assert.Equal(t, "Login successful", result.Message)
}

func TestLoginUser_InvalidCredentials(t *testing.T) {
	mockRepo, service := setupService(t)
	defer mockRepo.ctrl.Finish()

	ctx := context.Background()
	userAgent := "Mozilla/5.0"
	ipAddress := "192.168.1.1"

	userPassword := "Password123!"
	hashedPassword, err := password.HashPassword(userPassword)
	require.NoError(t, err)

	userID := uuid.New()
	existingUser := &domain.UserAuth{
		ID:           userID,
		Email:        "john.doe@example.com",
		PasswordHash: hashedPassword,
		FirstName:    "John",
		LastName:     "Doe",
		IsActive:     true,
	}

	input := usecase.LoginUserInput{
		Email:    "john.doe@example.com",
		Password: "WrongPassword123!",
	}

	mockRepo.EXPECT().
		GetUserByEmail(ctx, input.Email).
		Return(existingUser, nil)

	result, err := service.LoginUser(ctx, input, userAgent, ipAddress)

	assert.Error(t, err)
	assert.Equal(t, domain.ErrInvalidCredentials, err)
	assert.Empty(t, result.User.ID)
	assert.Empty(t, result.Session.Token)
}

func TestLoginUser_UserNotFound(t *testing.T) {
	mockRepo, service := setupService(t)
	defer mockRepo.ctrl.Finish()

	ctx := context.Background()
	userAgent := "Mozilla/5.0"
	ipAddress := "192.168.1.1"

	input := usecase.LoginUserInput{
		Email:    "nonexistent@example.com",
		Password: "Password123!",
	}

	mockRepo.EXPECT().
		GetUserByEmail(ctx, input.Email).
		Return(nil, domain.ErrUserNotFound)

	result, err := service.LoginUser(ctx, input, userAgent, ipAddress)

	assert.Error(t, err)
	assert.Equal(t, domain.ErrInvalidCredentials, err)
	assert.Empty(t, result.User.ID)
	assert.Empty(t, result.Session.Token)
}

func TestLoginUser_RepositoryError(t *testing.T) {
	mockRepo, service := setupService(t)
	defer mockRepo.ctrl.Finish()

	ctx := context.Background()
	userAgent := "Mozilla/5.0"
	ipAddress := "192.168.1.1"

	input := usecase.LoginUserInput{
		Email:    "test@example.com",
		Password: "Password123!",
	}

	mockRepo.EXPECT().
		GetUserByEmail(ctx, input.Email).
		Return(nil, assert.AnError)

	result, err := service.LoginUser(ctx, input, userAgent, ipAddress)

	assert.Error(t, err)
	assert.Equal(t, domain.ErrInvalidCredentials, err)
	assert.Empty(t, result.User.ID)
	assert.Empty(t, result.Session.Token)
}

func TestLoginUser_CreateSessionError(t *testing.T) {
	mockRepo, service := setupService(t)
	defer mockRepo.ctrl.Finish()

	ctx := context.Background()
	userAgent := "Mozilla/5.0"
	ipAddress := "192.168.1.1"

	userPassword := "Password123!"
	hashedPassword, err := password.HashPassword(userPassword)
	require.NoError(t, err)

	userID := uuid.New()
	existingUser := &domain.UserAuth{
		ID:           userID,
		Email:        "john.doe@example.com",
		PasswordHash: hashedPassword,
		FirstName:    "John",
		LastName:     "Doe",
		IsActive:     true,
	}

	input := usecase.LoginUserInput{
		Email:    "john.doe@example.com",
		Password: userPassword,
	}

	mockRepo.EXPECT().
		GetUserByEmail(ctx, input.Email).
		Return(existingUser, nil)

	mockRepo.EXPECT().
		CreateSession(ctx, gomock.Any()).
		Return(assert.AnError)

	result, err := service.LoginUser(ctx, input, userAgent, ipAddress)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to store session")
	assert.Empty(t, result.User.ID)
	assert.Empty(t, result.Session.Token)
}

func TestLogoutUser_Success(t *testing.T) {
	mockRepo, service := setupService(t)
	defer mockRepo.ctrl.Finish()

	ctx := context.Background()
	token := "valid_session_token_123"

	mockRepo.EXPECT().
		DeleteSessionByToken(ctx, token).
		Return(nil)

	result, err := service.LogoutUser(ctx, token)

	require.NoError(t, err)
	assert.Equal(t, "Logged out successfully", result.Message)
}

func TestLogoutUser_SessionNotFound(t *testing.T) {
	mockRepo, service := setupService(t)
	defer mockRepo.ctrl.Finish()

	ctx := context.Background()
	token := "nonexistent_session_token"

	mockRepo.EXPECT().
		DeleteSessionByToken(ctx, token).
		Return(domain.ErrSessionNotFound)

	result, err := service.LogoutUser(ctx, token)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to logout")
	assert.Empty(t, result.Message)
}
