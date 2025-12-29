package repository

import (
	"context"
	"errors"
	"time"

	"my_project/internal/auth/domain"
	"my_project/internal/database"

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

func (s *UserStore) CreateUser(ctx context.Context, user *domain.UserAuth) (*domain.UserAuth, error) {
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	query := `INSERT INTO users (email, password_hash, first_name, last_name, profile_picture, google_id, oauth_provider)
			  VALUES ($1, $2, $3, $4, $5, $6, $7::oauth_provider)
			  RETURNING id`

	err = tx.QueryRow(ctx, query, user.Email, user.PasswordHash, user.FirstName, user.LastName, user.ProfilePicture, user.GoogleID, user.OAuthProvider).Scan(&user.ID)
	if err != nil {
		return nil, err
	}

	subscriptionQuery := `INSERT INTO subscriptions (user_id, started_at)
						  VALUES ($1, $2)`
	_, err = tx.Exec(ctx, subscriptionQuery, user.ID.String(), time.Now())
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	return user, nil
}

func (s *UserStore) UserExistsByEmail(ctx context.Context, email string) (bool, error) {
	query := `SELECT 1 FROM users WHERE email = $1 LIMIT 1`

	var exists int
	err := s.db.Pool().QueryRow(ctx, query, email).Scan(&exists)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, err
	}

	return true, nil
}

func (s *UserStore) GetUserByEmail(ctx context.Context, email string) (*domain.UserAuth, error) {
	query := `SELECT id, email, password_hash, first_name, last_name, profile_picture, last_login_at, is_active, two_factor_enabled, two_factor_secret, recovery_codes
			  FROM users WHERE email = $1`

	user := &domain.UserAuth{}
	err := s.db.Pool().QueryRow(ctx, query, email).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.FirstName,
		&user.LastName,
		&user.ProfilePicture,
		&user.LastLoginAt,
		&user.IsActive,
		&user.TwoFactorEnabled,
		&user.TwoFactorSecret,
		&user.RecoveryCodes,
	)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (s *UserStore) GetUserByID(ctx context.Context, userID uuid.UUID) (*domain.UserAuth, error) {
	query := `SELECT id, email, password_hash, first_name, last_name, profile_picture, last_login_at, is_active, google_id, oauth_provider
			  FROM users WHERE id = $1`

	user := &domain.UserAuth{}
	err := s.db.Pool().QueryRow(ctx, query, userID).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.FirstName,
		&user.LastName,
		&user.ProfilePicture,
		&user.LastLoginAt,
		&user.IsActive,
		&user.GoogleID,
		&user.OAuthProvider,
	)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (s *UserStore) CreateSession(ctx context.Context, session *domain.Session) error {
	query := `INSERT INTO sessions (user_id, session_token, ip_address, user_agent, expires_at, created_at)
			  VALUES ($1, $2, $3, $4, $5, $6)`

	_, err := s.db.Pool().Exec(ctx, query,
		session.UserID,
		session.SessionToken,
		session.IpAddress,
		session.UserAgent,
		session.ExpiresAt,
		session.CreatedAt,
	)
	return err
}

func (s *UserStore) DeleteSessionByToken(ctx context.Context, token string) error {
	query := `DELETE FROM sessions WHERE session_token = $1`

	commandTag, err := s.db.Pool().Exec(ctx, query, token)
	if err != nil {
		return err
	}

	if commandTag.RowsAffected() == 0 {
		return domain.ErrSessionNotFound
	}

	return nil
}

func (s *UserStore) GetUserByGoogleID(ctx context.Context, googleID string) (*domain.UserAuth, error) {
	query := `SELECT id, email, password_hash, first_name, last_name, profile_picture, last_login_at, is_active, google_id, oauth_provider
			  FROM users WHERE google_id = $1 AND is_active = true`

	user := &domain.UserAuth{}
	err := s.db.Pool().QueryRow(ctx, query, googleID).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.FirstName,
		&user.LastName,
		&user.ProfilePicture,
		&user.LastLoginAt,
		&user.IsActive,
		&user.GoogleID,
		&user.OAuthProvider,
	)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (s *UserStore) GetSessionByToken(ctx context.Context, token string) (*domain.Session, error) {
	query := `SELECT id, user_id, session_token, ip_address, user_agent, expires_at, created_at
			  FROM sessions WHERE session_token = $1 AND expires_at > NOW()`

	session := &domain.Session{}
	err := s.db.Pool().QueryRow(ctx, query, token).Scan(
		&session.ID,
		&session.UserID,
		&session.SessionToken,
		&session.IpAddress,
		&session.UserAgent,
		&session.ExpiresAt,
		&session.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	return session, nil
}

func (s *UserStore) UpdateGoogleOAuth(ctx context.Context, userID uuid.UUID, googleID string, provider domain.OAuthProvider) error {
	query := `UPDATE users SET google_id = $2, oauth_provider = $3::oauth_provider, updated_at = NOW() WHERE id = $1`

	_, err := s.db.Pool().Exec(ctx, query, userID, googleID, provider)
	return err
}

func (s *UserStore) SetResetPasswordToken(ctx context.Context, email, token string, expiresAt time.Time) error {
	query := `UPDATE users SET reset_password_token = $2, reset_password_expires_at = $3,
			  is_resetting_password = true, updated_at = NOW()
			  WHERE email = $1`

	_, err := s.db.Pool().Exec(ctx, query, email, token, expiresAt)
	return err
}

func (s *UserStore) GetUserByResetToken(ctx context.Context, token string) (*domain.UserAuth, error) {
	query := `SELECT id, email, password_hash, first_name, last_name, profile_picture, last_login_at, is_active
			  FROM users
			  WHERE reset_password_token = $1
			  AND reset_password_expires_at > NOW()
			  AND is_resetting_password = true`

	user := &domain.UserAuth{}
	err := s.db.Pool().QueryRow(ctx, query, token).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.FirstName,
		&user.LastName,
		&user.ProfilePicture,
		&user.LastLoginAt,
		&user.IsActive,
	)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (s *UserStore) ResetPassword(ctx context.Context, userID uuid.UUID, newPasswordHash string) error {
	query := `UPDATE users SET password_hash = $2, reset_password_token = NULL,
			  reset_password_expires_at = NULL, is_resetting_password = false,
			  updated_at = NOW()
			  WHERE id = $1`

	_, err := s.db.Pool().Exec(ctx, query, userID, newPasswordHash)
	return err
}

func (s *UserStore) UpdateLastLoginAt(ctx context.Context, userID uuid.UUID) error {
	query := `UPDATE users SET last_login_at = NOW(), updated_at = NOW() WHERE id = $1`

	_, err := s.db.Pool().Exec(ctx, query, userID)
	return err
}

func (s *UserStore) CreateSubscription(ctx context.Context, subscription *domain.AuthSubscription) error {
	query := `INSERT INTO subscriptions (user_id, started_at)
			  VALUES ($1, $2)`

	_, err := s.db.Pool().Exec(ctx, query,
		subscription.UserID,
		time.Now(),
	)
	return err
}
