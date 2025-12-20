package usecase

import "my_project/internal/payment/domain"

type CreateCheckoutSessionInput struct {
	Plan     domain.SubscriptionPlan `json:"plan" form:"plan" validate:"required,oneof=BUSINESS PROFESSIONAL"`
	Quantity int                    `json:"quantity" form:"quantity" validate:"required,min=1,max=100"`
}

type CreateCheckoutSessionOutput struct {
	SessionID string `json:"session_id"`
	URL       string `json:"url"`
}
