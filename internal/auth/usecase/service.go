package usecase

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"my_project/internal/auth/domain"
	"my_project/internal/auth/repository"
	"my_project/pkg/logger"
	"my_project/pkg/password"

	"github.com/bluele/gcache"
)

type UserService struct {
	repo  repository.UserRepository
	cache gcache.Cache
}

func NewUserService(r repository.UserRepository) UserUsecase {
	return &UserService{
		repo:  r,
		cache: gcache.New(100).LRU().Expiration(time.Minute * 15).Build(),
	}
}

func (s *UserService) RegisterUser(ctx context.Context, input RegisterUserInput) (RegisterUserOutput, error) {
	if !domain.IsValidPassword(input.Password) {
		logger.Error("Password validation failed - format requirements not met")
		return RegisterUserOutput{}, domain.ErrInvalidUserPasswordFormat
	}

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

	token, err := domain.GenerateSecureToken()
	if err != nil {
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
			ID:             user.ID.String(),
			Email:          user.Email,
			FirstName:      user.FirstName,
			LastName:       user.LastName,
			ProfilePicture: user.ProfilePicture,
		},
		Session: SessionInfo{
			Token:     session.SessionToken,
			ExpiresAt: session.ExpiresAt.Format(time.RFC3339),
		},
		Message: "Login successful",
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

	return LogoutOutput{Message: "Logged out successfully"}, nil
}

func (s *UserService) LoginWithGoogle(ctx context.Context, input GoogleAuthInput, userAgent, ipAddress string) (GoogleAuthOutput, error) {
	googleUser, err := s.getGoogleUserInfo(input.AccessToken)
	if err != nil {
		logger.Error("Failed to get Google user info:", err)
		return GoogleAuthOutput{}, domain.ErrOAuthTokenInvalid
	}

	if !googleUser.EmailVerified {
		return GoogleAuthOutput{}, domain.ErrOAuthEmailRequired
	}

	// Check if user already exists with this Google ID
	user, err := s.repo.GetUserByGoogleID(ctx, googleUser.ID)
	if err == nil {
		return s.createSessionForExistingUser(ctx, user, userAgent, ipAddress)
	}

	// Check if user exists with this email but no Google OAuth yet
	user, err = s.repo.GetUserByEmail(ctx, googleUser.Email)
	if err == nil {
		err = s.repo.UpdateGoogleOAuth(ctx, user.ID, googleUser.ID, domain.AuthProviderGoogle)
		if err != nil {
			logger.Error("Failed to link Google account:", err)
			return GoogleAuthOutput{}, fmt.Errorf("failed to link Google account: %w", err)
		}
		logger.Info("Google account linked to existing user", "email", googleUser.Email)
		return s.createSessionForExistingUser(ctx, user, userAgent, ipAddress)
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

func (s *UserService) getGoogleUserInfo(accessToken string) (*GoogleUserInfo, error) {
	req, err := http.NewRequest("GET", "https://www.googleapis.com/oauth2/v2/userinfo", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, domain.ErrOAuthTokenInvalid
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var googleUser GoogleUserInfo
	err = json.Unmarshal(body, &googleUser)
	if err != nil {
		return nil, err
	}

	if googleUser.FirstName == "" && googleUser.LastName == "" && googleUser.Name != "" {
		parts := strings.Fields(googleUser.Name)
		if len(parts) >= 1 {
			googleUser.FirstName = parts[0]
		}
		if len(parts) >= 2 {
			googleUser.LastName = strings.Join(parts[1:], " ")
		}
	}

	return &googleUser, nil
}

func (s *UserService) createSessionForExistingUser(ctx context.Context, user *domain.UserAuth, userAgent, ipAddress string) (GoogleAuthOutput, error) {
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
			ID:             user.ID.String(),
			Email:          user.Email,
			FirstName:      user.FirstName,
			LastName:       user.LastName,
			ProfilePicture: user.ProfilePicture,
		},
		Session: SessionInfo{
			Token:     session.SessionToken,
			ExpiresAt: session.ExpiresAt.Format(time.RFC3339),
		},
		Message: "Login with Google successful",
	}, nil
}
