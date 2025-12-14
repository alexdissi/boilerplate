package usecase

import "context"

type UserUsecase interface {
	RegisterUser(ctx context.Context, input RegisterUserInput) (RegisterUserOutput, error)
	LoginUser(ctx context.Context, input LoginUserInput, userAgent, ipAddress string) (LoginUserOutput, error)
	LogoutUser(ctx context.Context, token string) (LogoutOutput, error)
}
