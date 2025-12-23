package usecase

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"mime/multipart"
	"slices"
	"strings"

	"my_project/internal/users/domain"
	"my_project/internal/users/repository"
	"my_project/pkg/crypto"
	"my_project/pkg/logger"
	"my_project/pkg/password"
	"my_project/pkg/uploadfiles"

	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const BucketFolder = "avatars"

type userUsecase struct {
	userRepo repository.UserRepository
	uploader *uploadfiles.Uploader
}

func NewUserUsecase(userRepo repository.UserRepository, uploader *uploadfiles.Uploader) UserUsecase {
	return &userUsecase{
		userRepo: userRepo,
		uploader: uploader,
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

func (u *userUsecase) UploadAvatar(ctx context.Context, userID string, fileHeader *multipart.FileHeader) (string, error) {
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return "", domain.ErrInvalidUserID
	}

	allowedExtensions := []string{".jpg", ".jpeg", ".png", ".gif", ".webp"}
	ext := strings.ToLower(strings.TrimSpace(fileHeader.Filename[strings.LastIndex(fileHeader.Filename, "."):]))
	isAllowed := slices.Contains(allowedExtensions, ext)
	if !isAllowed {
		return "", domain.ErrInvalidFileFormat
	}

	user, err := u.userRepo.GetUserByID(ctx, userUUID)
	if err != nil {
		logger.Error("failed to get user", err)
		return "", err
	}

	file, err := fileHeader.Open()
	if err != nil {
		logger.Error("failed to open file", err)
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	avatarURL, err := u.uploader.Upload(ctx, file, fileHeader, BucketFolder)
	if err != nil {
		logger.Error("failed to upload avatar", err)
		return "", fmt.Errorf("failed to upload avatar: %w", err)
	}

	if user.ProfilePicture != "" {
		err = u.uploader.Delete(ctx, user.ProfilePicture)
		if err != nil {
			logger.Error("failed to delete old avatar", err)
		}
	}

	err = u.userRepo.UpdateAvatar(ctx, userUUID, avatarURL)
	if err != nil {
		logger.Error("failed to update avatar URL", err)
		return "", err
	}

	return avatarURL, nil
}

func generateSecret() (string, error) {
	secret := make([]byte, 20)
	_, err := rand.Read(secret)
	if err != nil {
		return "", err
	}
	return base32.StdEncoding.EncodeToString(secret), nil
}

func generateRecoveryCodes() []string {
	codes := make([]string, 10)
	for i := range 10 {
		code := make([]byte, 4)
		rand.Read(code)
		codes[i] = fmt.Sprintf("%02x%02x-%02x%02x", code[0], code[1], code[2], code[3])
	}
	return codes
}

func (u *userUsecase) SetupTwoFactor(ctx context.Context, userID string) (TwoFactorSetupResponse, error) {
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return TwoFactorSetupResponse{}, domain.ErrInvalidUserID
	}

	user, err := u.userRepo.GetUserByID(ctx, userUUID)
	if err != nil {
		logger.Error("failed to get user", err)
		return TwoFactorSetupResponse{}, err
	}

	if user.TwoFactorEnabled {
		return TwoFactorSetupResponse{}, domain.ErrTwoFactorAlreadyEnabled
	}

	secret, err := generateSecret()
	if err != nil {
		logger.Error("failed to generate secret", err)
		return TwoFactorSetupResponse{}, domain.ErrFailedToGenerateTwoFactor
	}

	recoveryCodes := generateRecoveryCodes()

	key, err := otp.NewKeyFromURL(fmt.Sprintf(
		"otpauth://totp/Boilerplate:%s?secret=%s&issuer=Boilerplate&algorithm=SHA1&digits=6&period=30",
		user.Email,
		secret,
	))
	if err != nil {
		logger.Error("failed to create OTP key", err)
		return TwoFactorSetupResponse{}, domain.ErrFailedToGenerateTwoFactor
	}

	qrCode, err := key.Image(256, 256)
	if err != nil {
		logger.Error("failed to generate QR code", err)
		return TwoFactorSetupResponse{}, domain.ErrFailedToGenerateTwoFactor
	}

	qrCodeBase64 := fmt.Sprintf("data:image/png;base64,%s", qrCode)

	return TwoFactorSetupResponse{
		QRCode:        qrCodeBase64,
		Secret:        secret,
		RecoveryCodes: recoveryCodes,
	}, nil
}

func (u *userUsecase) EnableTwoFactor(ctx context.Context, userID string, req EnableTwoFactorRequest) error {
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return domain.ErrInvalidUserID
	}

	user, err := u.userRepo.GetUserByID(ctx, userUUID)
	if err != nil {
		logger.Error("failed to get user", err)
		return err
	}

	if user.TwoFactorEnabled {
		return domain.ErrTwoFactorAlreadyEnabled
	}

	valid := totp.Validate(req.Code, req.Secret)
	if !valid {
		return domain.ErrInvalidTwoFactorCode
	}

	recoveryCodes := generateRecoveryCodes()

	err = u.userRepo.EnableTwoFactor(ctx, userUUID, req.Secret, recoveryCodes)
	if err != nil {
		logger.Error("failed to enable two factor", err)
		return domain.ErrFailedToEnableTwoFactor
	}

	return nil
}

func (u *userUsecase) DisableTwoFactor(ctx context.Context, userID string, req DisableTwoFactorRequest) error {
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return domain.ErrInvalidUserID
	}

	user, err := u.userRepo.GetUserByID(ctx, userUUID)
	if err != nil {
		logger.Error("failed to get user", err)
		return err
	}

	if !user.TwoFactorEnabled {
		return domain.ErrTwoFactorNotEnabled
	}

	if user.TwoFactorSecret == nil {
		return domain.ErrTwoFactorNotEnabled
	}

	decryptedSecret, err := crypto.DecryptSecret(*user.TwoFactorSecret)
	if err != nil {
		logger.Error("failed to decrypt secret", err)
		return domain.ErrInvalidTwoFactorCode
	}

	valid := totp.Validate(req.Code, decryptedSecret)
	if !valid {
		return domain.ErrInvalidTwoFactorCode
	}

	err = u.userRepo.DisableTwoFactor(ctx, userUUID)
	if err != nil {
		logger.Error("failed to disable two factor", err)
		return domain.ErrFailedToDisableTwoFactor
	}

	return nil
}
