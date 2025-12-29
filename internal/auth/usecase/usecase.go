package usecase

import "context"

type UserUsecase interface {
	RegisterUser(ctx context.Context, input RegisterUserInput) (RegisterUserOutput, error)
	LoginUser(ctx context.Context, input LoginUserInput, userAgent, ipAddress string) (LoginUserOutput, error)
	VerifyTwoFactor(ctx context.Context, input VerifyTwoFactorInput, userAgent, ipAddress string) (VerifyTwoFactorOutput, error)
	LogoutUser(ctx context.Context, token string) (LogoutOutput, error)
	LoginWithGoogleInfo(ctx context.Context, userInfo *GoogleUserInfo, userAgent, ipAddress string) (GoogleAuthOutput, error)
	ForgotPassword(ctx context.Context, input ForgotPasswordInput) (ForgotPasswordOutput, error)
	ResetPassword(ctx context.Context, input ResetPasswordInput) (ResetPasswordOutput, error)
}
