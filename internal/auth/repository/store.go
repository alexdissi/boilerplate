package repository

import (
	"context"
	"errors"

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
	query := `INSERT INTO users (email, password_hash, first_name, last_name, profile_picture)
			  VALUES ($1, $2, $3, $4, $5)
			  RETURNING id`

	err := s.db.Pool().QueryRow(ctx, query, user.Email, user.PasswordHash, user.FirstName, user.LastName, user.ProfilePicture).Scan(&user.ID)
	if err != nil {
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
	query := `SELECT id, email, password_hash, first_name, last_name, profile_picture, last_login_at, is_active
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
	)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (s *UserStore) GetUserByID(ctx context.Context, userID uuid.UUID) (*domain.UserAuth, error) {
	query := `SELECT id, email, password_hash, first_name, last_name, profile_picture, last_login_at, is_active
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
