package usecase

import (
	"context"
	"net/http"
)

type PaymentUsecase interface {
	CreateCheckoutSession(ctx context.Context, id, email string, input CreateCheckoutSessionInput) (CreateCheckoutSessionOutput, error)
	HandleWebhook(r *http.Request) error
	CreatePortalSession(ctx context.Context, userID string) (CreatePortalSessionOutput, error)
}
