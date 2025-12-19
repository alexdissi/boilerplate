package usecase

import (
	"context"

	"github.com/labstack/echo/v4"
)

type PaymentUsecase interface {
	CreateCheckoutSession(ctx context.Context, id, email string, input CreateCheckoutSessionInput) (CreateCheckoutSessionOutput, error)
	HandleWebhook(c echo.Context) error
}
