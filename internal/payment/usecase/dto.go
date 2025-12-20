package usecase

import (
	"fmt"
	"my_project/internal/payment/domain"
	"strconv"
	"time"

	"github.com/google/uuid"
)

type CreateCheckoutSessionInput struct {
	Plan     domain.SubscriptionPlan `json:"plan" form:"plan" validate:"required,oneof=BUSINESS PROFESSIONAL"`
	Quantity int                     `json:"quantity" form:"quantity" validate:"required,min=1,max=100"`
}

type CreateCheckoutSessionOutput struct {
	SessionID string `json:"session_id"`
	URL       string `json:"url"`
}

type CreatePortalSessionOutput struct {
	URL string `json:"url"`
}

type subscriptionMetadata struct {
	UserID   uuid.UUID
	Plan     domain.SubscriptionPlan
	Quantity int
}

func newSubscriptionMetadata(meta map[string]string) (*subscriptionMetadata, error) {
	userID, ok := meta["user_id"]
	if !ok {
		return nil, fmt.Errorf("missing user_id in metadata")
	}
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return nil, fmt.Errorf("invalid user_id format: %w", err)
	}

	plan, ok := meta["plan"]
	if !ok || !domain.IsValidPlan(domain.SubscriptionPlan(plan)) {
		return nil, fmt.Errorf("missing or invalid plan in metadata")
	}

	quantity, err := strconv.Atoi(meta["quantity"])
	if err != nil || quantity <= 0 {
		quantity = 1
	}
	if quantity > 100 {
		quantity = 100
	}

	return &subscriptionMetadata{
		UserID:   userUUID,
		Plan:     domain.SubscriptionPlan(plan),
		Quantity: quantity,
	}, nil
}

func (m *subscriptionMetadata) toSubscription(customerID string) *domain.Subscription {
	return &domain.Subscription{
		UserID:             m.UserID,
		Plan:               m.Plan,
		CusID:              &customerID,
		LicenseCount:       m.Quantity,
		Status:             domain.StatusPending,
		Paid:               false,
		CurrentPeriodStart: time.Now().Unix(),
		CurrentPeriodEnd:   time.Now().Unix(),
		CancelAtPeriodEnd:  false,
		CreatedAt:          time.Now().Unix(),
		UpdatedAt:          time.Now().Unix(),
	}
}
