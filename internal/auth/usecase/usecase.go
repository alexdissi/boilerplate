package usecase

import "context"

//go:generate mockgen -destination=internal/auth/test/mock_user_usecase.go -package=test my_project/internal/auth/usecase UserUsecase
type UserUsecase interface {
	RegisterUser(ctx context.Context, input RegisterUserInput) (RegisterUserOutput, error)
	LoginUser(ctx context.Context, input LoginUserInput, userAgent, ipAddress string) (LoginUserOutput, error)
}
