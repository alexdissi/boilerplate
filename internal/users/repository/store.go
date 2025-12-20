package repository

import (
	"context"
	"errors"

	"my_project/internal/database"
	"my_project/internal/users/domain"

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

func (s *UserStore) GetUserByID(ctx context.Context, userID uuid.UUID) (*domain.User, error) {
	query := `
		SELECT id, email, first_name, last_name, profile_picture,
			   last_login_at, is_active
		FROM users
		WHERE id = $1`

	user := &domain.User{}
	err := s.db.Pool().QueryRow(ctx, query, userID).Scan(
		&user.ID,
		&user.Email,
		&user.FirstName,
		&user.LastName,
		&user.ProfilePicture,
		&user.LastLoginAt,
		&user.IsActive,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrUserNotFound
		}
		return nil, err
	}

	return user, nil
}
