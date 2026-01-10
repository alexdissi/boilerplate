package test

import (
	"context"
	"testing"
	"time"

	"my_project/internal/auth/domain"
	"my_project/internal/auth/usecase"
	"my_project/pkg/crypto"
	"my_project/pkg/logger"
	"my_project/pkg/mailer"
	"my_project/pkg/password"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func init() {
	logger.Init()
	err := crypto.SetEncryptionKey("test-encryption-key-for-testing-32-chars!!")
	if err != nil {
		panic(err)
	}
}

func setupService(t *testing.T) (*MockUserRepository, usecase.UserUsecase) {
	ctrl := gomock.NewController(t)
	mockRepo := NewMockUserRepository(ctrl)
	mockMailer := &mockMailer{
		sendCalls: make([]sendCall, 0),
	}

	service := usecase.NewUserService(mockRepo, mockMailer)
	return mockRepo, service
}

type mockMailer struct {
	sendCalls []sendCall
}

var _ mailer.Mailer = (*mockMailer)(nil)

type sendCall struct {
	to       string
	template string
	data     map[string]any
}

func (m *mockMailer) SendMail(to string, id string, data map[string]any) error {
	m.sendCalls = append(m.sendCalls, sendCall{
		to:       to,
		template: id,
		data:     data,
	})
	return nil
}

func (m *mockMailer) SendMailAsync(to string, id string, data map[string]any, operationName string) {
	// In tests, we execute synchronously to avoid race conditions
	_ = m.SendMail(to, id, data)
}

// ============================================================================
// REGISTER TESTS
// ============================================================================

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

// ============================================================================
// LOGIN TESTS
// ============================================================================

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
		ID:               userID,
		Email:            "john.doe@example.com",
		PasswordHash:     hashedPassword,
		FirstName:        "John",
		LastName:         "Doe",
		IsActive:         true,
		TwoFactorEnabled: false,
	}

	input := usecase.LoginUserInput{
		Email:    "john.doe@example.com",
		Password: userPassword,
	}

	mockRepo.EXPECT().
		GetUserByEmail(ctx, input.Email).
		Return(existingUser, nil)

	mockRepo.EXPECT().
		UpdateLastLoginAt(ctx, userID).
		Return(nil)

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
	assert.False(t, result.User.TwoFactorEnabled)
	require.NotNil(t, result.Session, "Session should not be nil on successful login")
	assert.NotEmpty(t, result.Session.Token)
	assert.NotEmpty(t, result.Session.ExpiresAt)
	assert.Equal(t, "Login successful", result.Message)
}

func TestLoginUser_With2FAEnabled(t *testing.T) {
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
		ID:               userID,
		Email:            "john.doe@example.com",
		PasswordHash:     hashedPassword,
		FirstName:        "John",
		LastName:         "Doe",
		IsActive:         true,
		TwoFactorEnabled: true,
	}

	input := usecase.LoginUserInput{
		Email:    "john.doe@example.com",
		Password: userPassword,
	}

	mockRepo.EXPECT().
		GetUserByEmail(ctx, input.Email).
		Return(existingUser, nil)

	result, err := service.LoginUser(ctx, input, userAgent, ipAddress)

	require.NoError(t, err)
	assert.Equal(t, existingUser.ID.String(), result.User.ID)
	assert.Equal(t, existingUser.Email, result.User.Email)
	assert.True(t, result.User.TwoFactorEnabled)
	assert.Nil(t, result.Session, "Session should be nil when 2FA is required")
	assert.Equal(t, "Two-factor authentication required", result.Message)
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
		ID:               userID,
		Email:            "john.doe@example.com",
		PasswordHash:     hashedPassword,
		FirstName:        "John",
		LastName:         "Doe",
		IsActive:         true,
		TwoFactorEnabled: false,
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
	assert.Nil(t, result.Session)
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
	assert.Nil(t, result.Session)
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
	assert.Nil(t, result.Session)
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
		ID:               userID,
		Email:            "john.doe@example.com",
		PasswordHash:     hashedPassword,
		FirstName:        "John",
		LastName:         "Doe",
		IsActive:         true,
		TwoFactorEnabled: false,
	}

	input := usecase.LoginUserInput{
		Email:    "john.doe@example.com",
		Password: userPassword,
	}

	mockRepo.EXPECT().
		GetUserByEmail(ctx, input.Email).
		Return(existingUser, nil)

	mockRepo.EXPECT().
		UpdateLastLoginAt(ctx, userID).
		Return(nil)

	mockRepo.EXPECT().
		CreateSession(ctx, gomock.Any()).
		Return(assert.AnError)

	result, err := service.LoginUser(ctx, input, userAgent, ipAddress)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to store session")
	assert.Empty(t, result.User.ID)
	assert.Nil(t, result.Session)
}

// ============================================================================
// TWO-FACTOR AUTHENTICATION TESTS
// ============================================================================

func TestVerifyTwoFactor_Success(t *testing.T) {
	mockRepo, service := setupService(t)
	defer mockRepo.ctrl.Finish()

	ctx := context.Background()
	userAgent := "Mozilla/5.0"
	ipAddress := "192.168.1.1"

	userID := uuid.New()

	// Generate real TOTP secret and code
	secret, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "MyProject",
		AccountName: "john.doe@example.com",
	})
	require.NoError(t, err)

	code, err := totp.GenerateCode(secret.Secret(), time.Now())
	require.NoError(t, err)

	encryptedSecret, err := crypto.EncryptSecret(secret.Secret())
	require.NoError(t, err)

	existingUser := &domain.UserAuth{
		ID:               userID,
		Email:            "john.doe@example.com",
		FirstName:        "John",
		LastName:         "Doe",
		TwoFactorEnabled: true,
		IsActive:         true,
	}

	twoFactor := &domain.UserTwoFactor{
		UserID:          userID,
		EncryptedSecret: encryptedSecret,
	}

	input := usecase.VerifyTwoFactorInput{
		Email: "john.doe@example.com",
		Code:  code,
	}

	mockRepo.EXPECT().
		GetUserByEmail(ctx, input.Email).
		Return(existingUser, nil)

	mockRepo.EXPECT().
		GetUserTwoFactor(ctx, userID).
		Return(twoFactor, nil)

	mockRepo.EXPECT().
		UpdateLastLoginAt(ctx, userID).
		Return(nil)

	mockRepo.EXPECT().
		CreateSession(ctx, gomock.Any()).
		Return(nil)

	result, err := service.VerifyTwoFactor(ctx, input, userAgent, ipAddress)

	require.NoError(t, err)
	require.NotNil(t, result.Session, "Session should not be nil after successful 2FA verification")
	assert.NotEmpty(t, result.Session.Token)
	assert.NotEmpty(t, result.Session.ExpiresAt)
	assert.Equal(t, "Two-factor verification successful", result.Message)
}

func TestVerifyTwoFactor_InvalidCode(t *testing.T) {
	mockRepo, service := setupService(t)
	defer mockRepo.ctrl.Finish()

	ctx := context.Background()
	userAgent := "Mozilla/5.0"
	ipAddress := "192.168.1.1"

	userID := uuid.New()

	secret, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "MyProject",
		AccountName: "john.doe@example.com",
	})
	require.NoError(t, err)

	encryptedSecret, err := crypto.EncryptSecret(secret.Secret())
	require.NoError(t, err)

	existingUser := &domain.UserAuth{
		ID:               userID,
		Email:            "john.doe@example.com",
		TwoFactorEnabled: true,
		IsActive:         true,
	}

	twoFactor := &domain.UserTwoFactor{
		UserID:          userID,
		EncryptedSecret: encryptedSecret,
	}

	input := usecase.VerifyTwoFactorInput{
		Email: "john.doe@example.com",
		Code:  "000000", // Invalid code
	}

	mockRepo.EXPECT().
		GetUserByEmail(ctx, input.Email).
		Return(existingUser, nil)

	mockRepo.EXPECT().
		GetUserTwoFactor(ctx, userID).
		Return(twoFactor, nil)

	result, err := service.VerifyTwoFactor(ctx, input, userAgent, ipAddress)

	assert.Error(t, err)
	assert.Equal(t, domain.ErrInvalidTwoFactorCode, err)
	assert.Nil(t, result.Session)
}

func TestVerifyTwoFactor_NotEnabled(t *testing.T) {
	mockRepo, service := setupService(t)
	defer mockRepo.ctrl.Finish()

	ctx := context.Background()
	userAgent := "Mozilla/5.0"
	ipAddress := "192.168.1.1"

	userID := uuid.New()
	existingUser := &domain.UserAuth{
		ID:               userID,
		Email:            "john.doe@example.com",
		TwoFactorEnabled: false,
		IsActive:         true,
	}

	input := usecase.VerifyTwoFactorInput{
		Email: "john.doe@example.com",
		Code:  "123456",
	}

	mockRepo.EXPECT().
		GetUserByEmail(ctx, input.Email).
		Return(existingUser, nil)

	result, err := service.VerifyTwoFactor(ctx, input, userAgent, ipAddress)

	assert.Error(t, err)
	assert.Equal(t, domain.ErrTwoFactorNotEnabled, err)
	assert.Nil(t, result.Session)
}

func TestVerifyTwoFactor_UserNotFound(t *testing.T) {
	mockRepo, service := setupService(t)
	defer mockRepo.ctrl.Finish()

	ctx := context.Background()
	userAgent := "Mozilla/5.0"
	ipAddress := "192.168.1.1"

	input := usecase.VerifyTwoFactorInput{
		Email: "nonexistent@example.com",
		Code:  "123456",
	}

	mockRepo.EXPECT().
		GetUserByEmail(ctx, input.Email).
		Return(nil, domain.ErrUserNotFound)

	result, err := service.VerifyTwoFactor(ctx, input, userAgent, ipAddress)

	assert.Error(t, err)
	assert.Equal(t, domain.ErrInvalidCredentials, err)
	assert.Nil(t, result.Session)
}

// ============================================================================
// LOGOUT TESTS
// ============================================================================

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

func TestLogoutUser_EmptyToken(t *testing.T) {
	_, service := setupService(t)

	ctx := context.Background()
	token := ""

	result, err := service.LogoutUser(ctx, token)

	assert.Error(t, err)
	assert.Equal(t, domain.ErrInvalidCredentials, err)
	assert.Empty(t, result.Message)
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

// ============================================================================
// FORGOT PASSWORD TESTS
// ============================================================================

func TestForgotPassword_Success(t *testing.T) {
	mockRepo, service := setupService(t)
	defer mockRepo.ctrl.Finish()

	ctx := context.Background()
	input := usecase.ForgotPasswordInput{
		Email: "john.doe@example.com",
	}

	userID := uuid.New()
	existingUser := &domain.UserAuth{
		ID:               userID,
		Email:            "john.doe@example.com",
		PasswordHash:     "hashed_password",
		FirstName:        "John",
		LastName:         "Doe",
		IsActive:         true,
		TwoFactorEnabled: false,
	}

	mockRepo.EXPECT().
		GetUserByEmail(ctx, input.Email).
		Return(existingUser, nil)

	mockRepo.EXPECT().
		SetResetPasswordToken(ctx, input.Email, gomock.Any(), gomock.Any()).
		Return(nil)

	result, err := service.ForgotPassword(ctx, input)

	require.NoError(t, err)
	assert.Equal(t, "If an account with this email exists, you will receive password reset instructions", result.Message)
}

func TestForgotPassword_UserNotFound(t *testing.T) {
	mockRepo, service := setupService(t)
	defer mockRepo.ctrl.Finish()

	ctx := context.Background()
	input := usecase.ForgotPasswordInput{
		Email: "nonexistent@example.com",
	}

	mockRepo.EXPECT().
		GetUserByEmail(ctx, input.Email).
		Return(nil, assert.AnError)

	result, err := service.ForgotPassword(ctx, input)

	// Should still return success to prevent email enumeration
	require.NoError(t, err)
	assert.Equal(t, "If an account with this email exists, you will receive password reset instructions", result.Message)
}

func TestForgotPassword_InvalidEmail(t *testing.T) {
	_, service := setupService(t)

	ctx := context.Background()
	input := usecase.ForgotPasswordInput{
		Email: "",
	}

	result, err := service.ForgotPassword(ctx, input)

	assert.Error(t, err)
	assert.Equal(t, domain.ErrInvalidUserEmail, err)
	assert.Empty(t, result.Message)
}

// ============================================================================
// RESET PASSWORD TESTS
// ============================================================================

func TestResetPassword_Success(t *testing.T) {
	mockRepo, service := setupService(t)
	defer mockRepo.ctrl.Finish()

	ctx := context.Background()
	input := usecase.ResetPasswordInput{
		Token:    "valid_reset_token_123",
		Password: "NewPassword123!",
	}

	userID := uuid.New()
	existingUser := &domain.UserAuth{
		ID:               userID,
		Email:            "john.doe@example.com",
		PasswordHash:     "hashed_password",
		FirstName:        "John",
		LastName:         "Doe",
		IsActive:         true,
		TwoFactorEnabled: false,
	}

	mockRepo.EXPECT().
		GetUserByResetToken(ctx, input.Token).
		Return(existingUser, nil)

	mockRepo.EXPECT().
		ResetPassword(ctx, userID, gomock.Any()).
		Return(nil)

	mockRepo.EXPECT().
		DeleteAllSessionsByUserID(ctx, userID).
		Return(nil)

	result, err := service.ResetPassword(ctx, input)

	require.NoError(t, err)
	assert.Equal(t, "Password reset successful", result.Message)
}

func TestResetPassword_InvalidToken(t *testing.T) {
	_, service := setupService(t)

	ctx := context.Background()
	input := usecase.ResetPasswordInput{
		Token:    "",
		Password: "NewPassword123!",
	}

	result, err := service.ResetPassword(ctx, input)

	assert.Error(t, err)
	assert.Equal(t, domain.ErrInvalidCredentials, err)
	assert.Empty(t, result.Message)
}

func TestResetPassword_TokenNotFound(t *testing.T) {
	mockRepo, service := setupService(t)
	defer mockRepo.ctrl.Finish()

	ctx := context.Background()
	input := usecase.ResetPasswordInput{
		Token:    "nonexistent_token_123",
		Password: "NewPassword123!",
	}

	mockRepo.EXPECT().
		GetUserByResetToken(ctx, input.Token).
		Return(nil, assert.AnError)

	result, err := service.ResetPassword(ctx, input)

	assert.Error(t, err)
	assert.Equal(t, domain.ErrInvalidCredentials, err)
	assert.Empty(t, result.Message)
}

// ============================================================================
// OAUTH / GOOGLE LOGIN TESTS
// ============================================================================

func TestLoginWithGoogleInfo_NewUser(t *testing.T) {
	mockRepo, service := setupService(t)
	defer mockRepo.ctrl.Finish()

	ctx := context.Background()
	userAgent := "Mozilla/5.0"
	ipAddress := "192.168.1.1"

	googleUser := &usecase.GoogleUserInfo{
		ID:            "google123",
		Email:         "john.doe@gmail.com",
		EmailVerified: true,
		FirstName:     "John",
		LastName:      "Doe",
		Picture:       "https://example.com/photo.jpg",
	}

	mockRepo.EXPECT().
		GetUserByGoogleID(ctx, googleUser.ID).
		Return(nil, domain.ErrUserNotFound)

	mockRepo.EXPECT().
		GetUserByEmail(ctx, googleUser.Email).
		Return(nil, domain.ErrUserNotFound)

	mockRepo.EXPECT().
		CreateUser(ctx, gomock.Any()).
		DoAndReturn(func(_ context.Context, user *domain.UserAuth) (*domain.UserAuth, error) {
			user.ID = uuid.New()
			assert.Equal(t, googleUser.Email, user.Email)
			assert.Equal(t, googleUser.FirstName, user.FirstName)
			assert.Equal(t, googleUser.LastName, user.LastName)
			assert.Equal(t, googleUser.Picture, user.ProfilePicture)
			assert.Equal(t, googleUser.ID, user.GoogleID)
			assert.Equal(t, domain.AuthProviderGoogle, user.OAuthProvider)
			return user, nil
		})

	mockRepo.EXPECT().
		UpdateLastLoginAt(ctx, gomock.Any()).
		Return(nil)

	mockRepo.EXPECT().
		CreateSession(ctx, gomock.Any()).
		Return(nil)

	result, err := service.LoginWithGoogleInfo(ctx, googleUser, userAgent, ipAddress)

	require.NoError(t, err)
	assert.NotEmpty(t, result.User.ID)
	assert.Equal(t, googleUser.Email, result.User.Email)
	require.NotNil(t, result.Session)
	assert.NotEmpty(t, result.Session.Token)
}

func TestLoginWithGoogleInfo_ExistingGoogleUser(t *testing.T) {
	mockRepo, service := setupService(t)
	defer mockRepo.ctrl.Finish()

	ctx := context.Background()
	userAgent := "Mozilla/5.0"
	ipAddress := "192.168.1.1"

	userID := uuid.New()
	existingUser := &domain.UserAuth{
		ID:            userID,
		Email:         "john.doe@gmail.com",
		GoogleID:      "google123",
		FirstName:     "John",
		LastName:      "Doe",
		OAuthProvider: domain.AuthProviderGoogle,
		IsActive:      true,
	}

	googleUser := &usecase.GoogleUserInfo{
		ID:            "google123",
		Email:         "john.doe@gmail.com",
		EmailVerified: true,
		FirstName:     "John",
		LastName:      "Doe",
	}

	mockRepo.EXPECT().
		GetUserByGoogleID(ctx, googleUser.ID).
		Return(existingUser, nil)

	mockRepo.EXPECT().
		UpdateLastLoginAt(ctx, userID).
		Return(nil)

	mockRepo.EXPECT().
		CreateSession(ctx, gomock.Any()).
		Return(nil)

	result, err := service.LoginWithGoogleInfo(ctx, googleUser, userAgent, ipAddress)

	require.NoError(t, err)
	assert.Equal(t, userID.String(), result.User.ID)
	assert.Equal(t, googleUser.Email, result.User.Email)
	require.NotNil(t, result.Session)
	assert.NotEmpty(t, result.Session.Token)
}

func TestLoginWithGoogleInfo_EmailNotVerified(t *testing.T) {
	_, service := setupService(t)

	ctx := context.Background()
	userAgent := "Mozilla/5.0"
	ipAddress := "192.168.1.1"

	googleUser := &usecase.GoogleUserInfo{
		ID:            "google123",
		Email:         "john.doe@gmail.com",
		EmailVerified: false,
		FirstName:     "John",
		LastName:      "Doe",
	}

	result, err := service.LoginWithGoogleInfo(ctx, googleUser, userAgent, ipAddress)

	assert.Error(t, err)
	assert.Equal(t, domain.ErrOAuthEmailRequired, err)
	assert.Empty(t, result.User.ID)
}

func TestLoginWithGoogleInfo_AccountLinkingRequired(t *testing.T) {
	mockRepo, service := setupService(t)
	defer mockRepo.ctrl.Finish()

	ctx := context.Background()
	userAgent := "Mozilla/5.0"
	ipAddress := "192.168.1.1"

	userID := uuid.New()
	existingUser := &domain.UserAuth{
		ID:            userID,
		Email:         "john.doe@gmail.com",
		PasswordHash:  "hashedpassword",
		FirstName:     "John",
		LastName:      "Doe",
		OAuthProvider: domain.AuthProviderEmail,
		IsActive:      true,
	}

	googleUser := &usecase.GoogleUserInfo{
		ID:            "google123",
		Email:         "john.doe@gmail.com",
		EmailVerified: true,
		FirstName:     "John",
		LastName:      "Doe",
	}

	mockRepo.EXPECT().
		GetUserByGoogleID(ctx, googleUser.ID).
		Return(nil, domain.ErrUserNotFound)

	mockRepo.EXPECT().
		GetUserByEmail(ctx, googleUser.Email).
		Return(existingUser, nil)

	result, err := service.LoginWithGoogleInfo(ctx, googleUser, userAgent, ipAddress)

	assert.Error(t, err)
	assert.Equal(t, domain.ErrOAuthAccountLinkingRequired, err)
	assert.Empty(t, result.User.ID)
}
