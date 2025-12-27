package repository

import (
	"context"
	"errors"

	"my_project/internal/database"
	"my_project/internal/users/domain"
	"my_project/pkg/crypto"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type UserStore struct {
	db database.Service
}

func NewUserStore(db database.Service) UserRepository {
	return &UserStore{
		db: db,
	}
}

func (s *UserStore) GetPublicProfileByID(ctx context.Context, userID uuid.UUID) (*domain.User, error) {
	query := `
		SELECT id, email, first_name, last_name, profile_picture
		FROM users
		WHERE id = $1 AND is_active = true`

	profile := &domain.User{}
	err := s.db.Pool().QueryRow(ctx, query, userID).Scan(
		&profile.ID,
		&profile.Email,
		&profile.FirstName,
		&profile.LastName,
		&profile.ProfilePicture,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrUserNotFound
		}
		return nil, err
	}

	return profile, nil
}

func (s *UserStore) UpdateUser(ctx context.Context, user *domain.User) (*domain.User, error) {
	query := `
		UPDATE users
		SET email = $2, first_name = $3, last_name = $4
		WHERE id = $1
		RETURNING id, email, first_name, last_name, profile_picture,
				  last_login_at, is_active, deleted_at`

	updatedUser := &domain.User{}
	err := s.db.Pool().QueryRow(ctx, query,
		user.ID,
		user.Email,
		user.FirstName,
		user.LastName,
	).Scan(
		&updatedUser.ID,
		&updatedUser.Email,
		&updatedUser.FirstName,
		&updatedUser.LastName,
		&updatedUser.ProfilePicture,
		&updatedUser.LastLoginAt,
		&updatedUser.IsActive,
		&updatedUser.DeletedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrUserNotFound
		}
		return nil, err
	}

	return updatedUser, nil
}

func (s *UserStore) UpdatePassword(ctx context.Context, userID uuid.UUID, passwordHash string) error {
	query := `UPDATE users SET password_hash = $2, updated_at = NOW() WHERE id = $1`

	commandTag, err := s.db.Pool().Exec(ctx, query, userID, passwordHash)
	if err != nil {
		return err
	}

	if commandTag.RowsAffected() == 0 {
		return domain.ErrUserNotFound
	}

	return nil
}

func (s *UserStore) DeleteUser(ctx context.Context, userID uuid.UUID) error {
	query := `UPDATE users SET is_active = false, deleted_at = NOW() + INTERVAL '6 months', updated_at = NOW() WHERE id = $1 AND is_active = true`

	commandTag, err := s.db.Pool().Exec(ctx, query, userID)
	if err != nil {
		return err
	}

	if commandTag.RowsAffected() == 0 {
		return domain.ErrUserNotFound
	}
	return nil
}
func (s *UserStore) UpdateAvatar(ctx context.Context, userID uuid.UUID, avatarURL string) error {
	query := `UPDATE users SET profile_picture = $2, updated_at = NOW() WHERE id = $1`

	commandTag, err := s.db.Pool().Exec(ctx, query, userID, avatarURL)
	if err != nil {
		return err
	}

	if commandTag.RowsAffected() == 0 {
		return domain.ErrUserNotFound
	}

	return nil
}

func (s *UserStore) EnableTwoFactor(ctx context.Context, userID uuid.UUID, secret string, recoveryCodes []string) error {
	encryptedSecret, err := crypto.EncryptSecret(secret)
	if err != nil {
		return err
	}

	query := `UPDATE users SET two_factor_enabled = true, two_factor_secret = $2, recovery_codes = $3, updated_at = NOW() WHERE id = $1`

	commandTag, err := s.db.Pool().Exec(ctx, query, userID, encryptedSecret, recoveryCodes)
	if err != nil {
		return err
	}

	if commandTag.RowsAffected() == 0 {
		return domain.ErrUserNotFound
	}

	return nil
}

func (s *UserStore) DisableTwoFactor(ctx context.Context, userID uuid.UUID) error {
	query := `UPDATE users SET two_factor_enabled = false, two_factor_secret = NULL, recovery_codes = NULL, updated_at = NOW() WHERE id = $1`

	commandTag, err := s.db.Pool().Exec(ctx, query, userID)
	if err != nil {
		return err
	}

	if commandTag.RowsAffected() == 0 {
		return domain.ErrUserNotFound
	}

	return nil
}
