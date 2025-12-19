package repository

import (
	"context"
	"database/sql"
	"my_project/internal/database"
	"my_project/internal/payment/domain"
	"time"

	sq "github.com/Masterminds/squirrel"
)

type subscriptionStore struct {
	db database.Service
}

func NewSubscriptionRepository(db database.Service) SubscriptionRepository {
	return &subscriptionStore{db: db}
}

func (s *subscriptionStore) CreateSubscription(ctx context.Context, sub *domain.Subscription) error {
	query := sq.Insert("subscriptions").
		Columns("user_id", "plan", "sub_id", "cus_id", "status", "paid", "license_count", "started_at", "expires_at", "created", "updated").
		Values(sub.UserID, sub.Plan, sub.SubID, sub.CusID, sub.Status, sub.Paid, sub.LicenseCount,
			time.Unix(sub.CurrentPeriodStart, 0), time.Unix(sub.CurrentPeriodEnd, 0), time.Now(), time.Now()).
		Suffix("ON CONFLICT (user_id) DO UPDATE SET plan = EXCLUDED.plan, sub_id = EXCLUDED.sub_id, cus_id = EXCLUDED.cus_id, status = EXCLUDED.status, paid = EXCLUDED.paid, license_count = EXCLUDED.license_count, started_at = EXCLUDED.started_at, expires_at = EXCLUDED.expires_at, updated = EXCLUDED.updated").
		PlaceholderFormat(sq.Dollar)

	sqlStr, args, err := query.ToSql()
	if err != nil {
		return err
	}

	_, err = s.db.Pool().Exec(ctx, sqlStr, args...)
	return err
}

func (s *subscriptionStore) GetSubscriptionByUserID(ctx context.Context, userID string) (*domain.Subscription, error) {
	query := sq.Select("user_id", "plan", "sub_id", "cus_id", "status", "paid", "license_count", "started_at", "expires_at", "created", "updated").
		From("subscriptions").
		Where(sq.Eq{"user_id": userID}).
		PlaceholderFormat(sq.Dollar)

	return s.queryOne(ctx, query)
}

func (s *subscriptionStore) GetSubscriptionBySubID(ctx context.Context, subID string) (*domain.Subscription, error) {
	query := sq.Select("user_id", "plan", "sub_id", "cus_id", "status", "paid", "license_count", "started_at", "expires_at", "created", "updated").
		From("subscriptions").
		Where(sq.Eq{"sub_id": subID}).
		PlaceholderFormat(sq.Dollar)

	return s.queryOne(ctx, query)
}

func (s *subscriptionStore) GetSubscriptionByCustomerID(ctx context.Context, customerID string) (*domain.Subscription, error) {
	query := sq.Select("user_id", "plan", "sub_id", "cus_id", "status", "paid", "license_count", "started_at", "expires_at", "created", "updated").
		From("subscriptions").
		Where(sq.Eq{"cus_id": customerID}).
		OrderBy("created DESC").
		Limit(1).
		PlaceholderFormat(sq.Dollar)

	return s.queryOne(ctx, query)
}

func (s *subscriptionStore) UpdateSubscription(ctx context.Context, sub *domain.Subscription) error {
	query := sq.Update("subscriptions").
		Set("plan", sub.Plan).
		Set("sub_id", sub.SubID).
		Set("cus_id", sub.CusID).
		Set("status", sub.Status).
		Set("paid", sub.Paid).
		Set("license_count", sub.LicenseCount).
		Set("started_at", time.Unix(sub.CurrentPeriodStart, 0)).
		Set("expires_at", time.Unix(sub.CurrentPeriodEnd, 0)).
		Set("updated", time.Now()).
		Where(sq.Eq{"user_id": sub.UserID}).
		PlaceholderFormat(sq.Dollar)

	sqlStr, args, err := query.ToSql()
	if err != nil {
		return err
	}

	_, err = s.db.Pool().Exec(ctx, sqlStr, args...)
	return err
}

func (s *subscriptionStore) queryOne(ctx context.Context, query sq.SelectBuilder) (*domain.Subscription, error) {
	sqlStr, args, err := query.ToSql()
	if err != nil {
		return nil, err
	}

	var sub domain.Subscription
	var startedAt, expiresAt, createdAt, updatedAt sql.NullTime
	var stripeSubID, stripeCustID sql.NullString

	err = s.db.Pool().QueryRow(ctx, sqlStr, args...).Scan(
		&sub.UserID,
		&sub.Plan,
		&stripeSubID,
		&stripeCustID,
		&sub.Status,
		&sub.Paid,
		&sub.LicenseCount,
		&startedAt,
		&expiresAt,
		&createdAt,
		&updatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, domain.ErrSubscriptionNotFound
		}
		return nil, err
	}

	if stripeSubID.Valid {
		sub.SubID = &stripeSubID.String
	}
	if stripeCustID.Valid {
		sub.CusID = stripeCustID.String
	}
	if startedAt.Valid {
		sub.CurrentPeriodStart = startedAt.Time.Unix()
	}
	if expiresAt.Valid {
		sub.CurrentPeriodEnd = expiresAt.Time.Unix()
	}
	if createdAt.Valid {
		sub.CreatedAt = createdAt.Time.Unix()
	}
	if updatedAt.Valid {
		sub.UpdatedAt = updatedAt.Time.Unix()
	}

	return &sub, nil
}
