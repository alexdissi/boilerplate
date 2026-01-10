package usecase

import (
	"context"
	"fmt"
	"os"
	"time"

	"my_project/internal/auth/domain"
	"my_project/internal/auth/repository"
	sessionMiddleware "my_project/internal/middleware"
	"my_project/pkg/crypto"
	"my_project/pkg/logger"
	"my_project/pkg/mailer"
	"my_project/pkg/password"

	"github.com/bluele/gcache"
	"github.com/pquerna/otp/totp"
)

type UserService struct {
	repo   repository.UserRepository
	cache  gcache.Cache
	mailer mailer.Mailer
	appUrl string
}

func NewUserService(r repository.UserRepository, m mailer.Mailer) UserUsecase {
	return &UserService{
		repo:   r,
		cache:  gcache.New(100).LRU().Expiration(time.Minute * 15).Build(),
		mailer: m,
		appUrl: os.Getenv("APP_URL"),
	}
}

func (s *UserService) RegisterUser(ctx context.Context, input RegisterUserInput) (RegisterUserOutput, error) {
	exists, err := s.repo.UserExistsByEmail(ctx, input.Email)
	if err != nil {
		logger.Error("Repository error checking user existence")
		return RegisterUserOutput{}, fmt.Errorf("failed to check user existence: %w", err)
	}
	if exists {
		return RegisterUserOutput{}, domain.ErrUserAlreadyExists
	}

	hashedPassword, err := password.HashPassword(input.Password)
	if err != nil {
		logger.Error("Password hashing error:", err)
		return RegisterUserOutput{}, fmt.Errorf("failed to hash password: %w", err)
	}

	user := &domain.UserAuth{
		Email:          input.Email,
		PasswordHash:   hashedPassword,
		FirstName:      input.FirstName,
		LastName:       input.LastName,
		ProfilePicture: domain.GenerateProfilePicture(input.FirstName, input.LastName),
		OAuthProvider:  domain.AuthProviderEmail,
	}

	if err := user.Validate(); err != nil {
		logger.Error("User validation error during registration")
		return RegisterUserOutput{}, err
	}

	createdUser, err := s.repo.CreateUser(ctx, user)
	if err != nil {
		logger.Error("Repository error creating user:", err)
		return RegisterUserOutput{}, fmt.Errorf("failed to create user: %w", err)
	}

	s.mailer.SendMailAsync(createdUser.Email, "welcome-email", map[string]any{
		"NAME": createdUser.FirstName + " " + createdUser.LastName,
		"MAIL": createdUser.Email,
	}, "welcome-email")

	return RegisterUserOutput{
		ID:      createdUser.ID.String(),
		Email:   createdUser.Email,
		Message: "User created successfully",
	}, nil
}

func (s *UserService) LoginUser(ctx context.Context, input LoginUserInput, userAgent, ipAddress string) (LoginUserOutput, error) {
	attempts, err := s.cache.Get(input.Email)
	if err == nil {
		if attempts.(int) >= domain.MaxLoginAttempts {
			logger.Error("Rate limit exceeded for login attempts")
			return LoginUserOutput{}, domain.ErrTooManyLoginAttempts
		}
	}

	user, err := s.repo.GetUserByEmail(ctx, input.Email)
	if err != nil {
		logger.Error("Repository error fetching user:", err)
		return LoginUserOutput{}, domain.ErrInvalidCredentials
	}

	passwordMatch, err := password.ComparePassword(user.PasswordHash, input.Password)
	if err != nil {
		return LoginUserOutput{}, domain.ErrInvalidCredentials
	}

	if !passwordMatch {
		currentAttempts := 1
		if attempts != nil {
			currentAttempts = attempts.(int) + 1
		}

		if err := s.cache.Set(input.Email, currentAttempts); err != nil {
			logger.Error("Cache error updating login attempts")
		}

		return LoginUserOutput{}, domain.ErrInvalidCredentials
	}

	s.cache.Remove(input.Email)

	if user.TwoFactorEnabled {
		return LoginUserOutput{
			User: UserInfo{
				ID:    user.ID.String(),
				Email: user.Email,
			},
			Message:           "Two-factor authentication required",
			RequiresTwoFactor: true,
		}, nil
	}

	err = s.repo.UpdateLastLoginAt(ctx, user.ID)
	if err != nil {
		logger.Error("Failed to update last login timestamp:", err)
	}

	token, err := domain.GenerateSecureToken()
	if err != nil {
		logger.Error("Failed to generate session token:", err)
		return LoginUserOutput{}, fmt.Errorf("failed to generate session token: %w", err)
	}

	session := &domain.Session{
		UserID:       user.ID,
		SessionToken: token,
		IpAddress:    ipAddress,
		UserAgent:    userAgent,
		ExpiresAt:    time.Now().Add(domain.SessionDurationMinutes * time.Minute),
		CreatedAt:    time.Now(),
	}

	if err := s.repo.CreateSession(ctx, session); err != nil {
		logger.Error("Failed to store session in database")
		return LoginUserOutput{}, fmt.Errorf("failed to store session: %w", err)
	}

	return LoginUserOutput{
		User: UserInfo{
			ID:    user.ID.String(),
			Email: user.Email,
		},
		Session: SessionInfo{
			Token:     session.SessionToken,
			ExpiresAt: session.ExpiresAt.Format(time.RFC3339),
		},
		Message:           "Login successful",
		RequiresTwoFactor: false,
	}, nil
}

func (s *UserService) VerifyTwoFactor(ctx context.Context, input VerifyTwoFactorInput, userAgent, ipAddress string) (VerifyTwoFactorOutput, error) {
	user, err := s.repo.GetUserByEmail(ctx, input.Email)
	if err != nil {
		logger.Error("Repository error fetching user:", err)
		return VerifyTwoFactorOutput{}, domain.ErrInvalidCredentials
	}

	if !user.TwoFactorEnabled {
		return VerifyTwoFactorOutput{}, domain.ErrTwoFactorNotEnabled
	}

	// Get 2FA data from separate table
	twoFactor, err := s.repo.GetUserTwoFactor(ctx, user.ID)
	if err != nil {
		logger.Error("Failed to get 2FA data:", err)
		return VerifyTwoFactorOutput{}, domain.ErrTwoFactorNotEnabled
	}

	if !twoFactor.Enabled {
		return VerifyTwoFactorOutput{}, domain.ErrTwoFactorNotEnabled
	}

	decryptedSecret, err := crypto.DecryptSecret(twoFactor.EncryptedSecret)
	if err != nil {
		logger.Error("Failed to decrypt 2FA secret:", err)
		return VerifyTwoFactorOutput{}, domain.ErrInvalidTwoFactorCode
	}

	valid := totp.Validate(input.Code, decryptedSecret)
	if !valid {
		return VerifyTwoFactorOutput{}, domain.ErrInvalidTwoFactorCode
	}

	err = s.repo.UpdateLastLoginAt(ctx, user.ID)
	if err != nil {
		logger.Error("Failed to update last login timestamp:", err)
	}

	token, err := domain.GenerateSecureToken()
	if err != nil {
		logger.Error("Failed to generate session token:", err)
		return VerifyTwoFactorOutput{}, fmt.Errorf("failed to generate session token: %w", err)
	}

	session := &domain.Session{
		UserID:       user.ID,
		SessionToken: token,
		IpAddress:    ipAddress,
		UserAgent:    userAgent,
		ExpiresAt:    time.Now().Add(domain.SessionDurationMinutes * time.Minute),
		CreatedAt:    time.Now(),
	}

	if err := s.repo.CreateSession(ctx, session); err != nil {
		logger.Error("Failed to store session in database")
		return VerifyTwoFactorOutput{}, fmt.Errorf("failed to store session: %w", err)
	}

	return VerifyTwoFactorOutput{
		Session: SessionInfo{
			Token:     session.SessionToken,
			ExpiresAt: session.ExpiresAt.Format(time.RFC3339),
		},
		Message: "Two-factor verification successful",
	}, nil
}

func (s *UserService) LogoutUser(ctx context.Context, token string) (LogoutOutput, error) {
	if token == "" {
		logger.Error("Logout attempted with empty token")
		return LogoutOutput{}, domain.ErrInvalidCredentials
	}

	err := s.repo.DeleteSessionByToken(ctx, token)
	if err != nil {
		logger.Error("Failed to delete session during logout")
		return LogoutOutput{}, fmt.Errorf("failed to logout: %w", err)
	}

	sessionMiddleware.InvalidateSessionCache(token)

	return LogoutOutput{Message: "Logged out successfully"}, nil
}

func (s *UserService) ForgotPassword(ctx context.Context, input ForgotPasswordInput) (ForgotPasswordOutput, error) {
	if input.Email == "" {
		return ForgotPasswordOutput{}, domain.ErrInvalidUserEmail
	}

	// Rate limiting for forgot password requests
	cacheKey := "forgot_pwd:" + input.Email
	attempts, err := s.cache.Get(cacheKey)
	if err == nil {
		if attempts.(int) >= domain.MaxForgotPasswordAttempts {
			logger.Error("Rate limit exceeded for forgot password")
			return ForgotPasswordOutput{}, domain.ErrTooManyForgotPasswordAttempts
		}
	}

	user, err := s.repo.GetUserByEmail(ctx, input.Email)
	if err != nil {
		return ForgotPasswordOutput{
			Message: "If an account with this email exists, you will receive password reset instructions",
		}, nil
	}

	resetToken, err := domain.GenerateSecureToken()
	if err != nil {
		logger.Error("Failed to generate reset token:", err)
		return ForgotPasswordOutput{}, fmt.Errorf("failed to generate reset token: %w", err)
	}

	expiresAt := time.Now().Add(time.Hour * 1)
	err = s.repo.SetResetPasswordToken(ctx, user.Email, resetToken, expiresAt)
	if err != nil {
		logger.Error("Failed to set reset password token:", err)
		return ForgotPasswordOutput{}, fmt.Errorf("failed to set reset token: %w", err)
	}

	// Increment forgot password attempts
	currentAttempts := 1
	if attempts != nil {
		currentAttempts = attempts.(int) + 1
	}
	if err := s.cache.Set(cacheKey, currentAttempts); err != nil {
		logger.Error("Cache error updating forgot password attempts")
	}

	resetLink := s.appUrl + "/reset-password?token=" + resetToken
	s.mailer.SendMailAsync(user.Email, "forgot-password", map[string]any{
		"RESET_LINK": resetLink,
	}, "forgot-password")

	return ForgotPasswordOutput{
		Message: "If an account with this email exists, you will receive password reset instructions",
	}, nil
}

func (s *UserService) ResetPassword(ctx context.Context, input ResetPasswordInput) (ResetPasswordOutput, error) {
	if input.Token == "" {
		return ResetPasswordOutput{}, domain.ErrInvalidCredentials
	}

	user, err := s.repo.GetUserByResetToken(ctx, input.Token)
	if err != nil {
		logger.Error("Invalid or expired reset token used")
		return ResetPasswordOutput{}, domain.ErrInvalidCredentials
	}

	hashedPassword, err := password.HashPassword(input.Password)
	if err != nil {
		logger.Error("Failed to hash new password:", err)
		return ResetPasswordOutput{}, fmt.Errorf("failed to hash password: %w", err)
	}

	err = s.repo.ResetPassword(ctx, user.ID, hashedPassword)
	if err != nil {
		logger.Error("Failed to reset password:", err)
		return ResetPasswordOutput{}, fmt.Errorf("failed to reset password: %w", err)
	}

	err = s.repo.DeleteAllSessionsByUserID(ctx, user.ID)
	if err != nil {
		logger.Error("Failed to invalidate sessions after password reset:", err)
	}

	return ResetPasswordOutput{
		Message: "Password reset successful",
	}, nil
}

func (s *UserService) createSessionForExistingUser(ctx context.Context, user *domain.UserAuth, userAgent, ipAddress string) (GoogleAuthOutput, error) {
	err := s.repo.UpdateLastLoginAt(ctx, user.ID)
	if err != nil {
		logger.Error("Failed to update last login timestamp for Google user:", err)
		return GoogleAuthOutput{}, fmt.Errorf("failed to update last login: %w", err)
	}

	token, err := domain.GenerateSecureToken()
	if err != nil {
		return GoogleAuthOutput{}, fmt.Errorf("failed to generate session token: %w", err)
	}

	session := &domain.Session{
		UserID:       user.ID,
		SessionToken: token,
		IpAddress:    ipAddress,
		UserAgent:    userAgent,
		ExpiresAt:    time.Now().Add(domain.SessionDurationMinutes * time.Minute),
		CreatedAt:    time.Now(),
	}

	if err := s.repo.CreateSession(ctx, session); err != nil {
		logger.Error("Failed to store session for Google user:", err)
		return GoogleAuthOutput{}, fmt.Errorf("failed to store session: %w", err)
	}

	return GoogleAuthOutput{
		User: UserInfo{
			ID:    user.ID.String(),
			Email: user.Email,
		},
		Session: SessionInfo{
			Token:     session.SessionToken,
			ExpiresAt: session.ExpiresAt.Format(time.RFC3339),
		},
		Message: "Login with Google successful",
	}, nil
}

func (s *UserService) LoginWithGoogleInfo(ctx context.Context, googleUser *GoogleUserInfo, userAgent, ipAddress string) (GoogleAuthOutput, error) {
	if !googleUser.EmailVerified {
		return GoogleAuthOutput{}, domain.ErrOAuthEmailRequired
	}

	user, err := s.repo.GetUserByGoogleID(ctx, googleUser.ID)
	if err == nil {
		return s.createSessionForExistingUser(ctx, user, userAgent, ipAddress)
	}

	user, err = s.repo.GetUserByEmail(ctx, googleUser.Email)
	if err == nil {
		// Account exists with this email but not linked to Google
		// For security reasons, we don't auto-link accounts
		// User should login with email/password first, then link Google in settings
		logger.Info("User tried to login with Google but account exists with email/password", "email", googleUser.Email)
		return GoogleAuthOutput{}, domain.ErrOAuthAccountLinkingRequired
	}

	newUser := &domain.UserAuth{
		Email:          googleUser.Email,
		FirstName:      googleUser.FirstName,
		LastName:       googleUser.LastName,
		ProfilePicture: googleUser.Picture,
		GoogleID:       googleUser.ID,
		OAuthProvider:  domain.AuthProviderGoogle,
		IsActive:       true,
	}

	createdUser, err := s.repo.CreateUser(ctx, newUser)
	if err != nil {
		logger.Error("Failed to create Google user:", err)
		return GoogleAuthOutput{}, fmt.Errorf("failed to create user: %w", err)
	}

	return s.createSessionForExistingUser(ctx, createdUser, userAgent, ipAddress)
}
