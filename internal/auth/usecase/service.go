package usecase

import (
	"context"
	"fmt"
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
		logger.Error("Password validation failed - invalid format")
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
		logger.Error("User validation error for:", input.Email, "Error:", err)
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
		if attempts.(int) >= 5 {
			logger.Error("Too many login attempts for:", input.Email)
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
		ExpiresAt:    time.Now().Add(domain.SessionDurationMinutes * time.Minute).Format(time.RFC3339),
		CreatedAt:    time.Now().Format(time.RFC3339),
	}

	if err := s.repo.CreateSession(ctx, session); err != nil {
		logger.Error("Failed to store session for user:", user.ID, "error:", err)
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
			ExpiresAt: session.ExpiresAt,
		},
		Message: "Login successful",
	}, nil
}
