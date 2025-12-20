package domain

import "errors"

var (
	ErrInvalidPlan           = errors.New("invalid subscription plan")
	ErrUserAlreadySubscribed = errors.New("user already has an active subscription")
	ErrSubscriptionNotFound  = errors.New("subscription not found")
	ErrWebhook               = errors.New("webhook error")
)
