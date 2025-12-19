package repository

import (
	"context"
	"my_project/internal/payment/domain"
)

type SubscriptionRepository interface {
	CreateSubscription(ctx context.Context, subscription *domain.Subscription) error
	GetSubscriptionByUserID(ctx context.Context, userID string) (*domain.Subscription, error)
	GetSubscriptionBySubID(ctx context.Context, subID string) (*domain.Subscription, error)
	GetSubscriptionByCustomerID(ctx context.Context, customerID string) (*domain.Subscription, error)
	UpdateSubscription(ctx context.Context, subscription *domain.Subscription) error
}
