package handler

import (
	"errors"
	"my_project/internal/middleware"
	"my_project/internal/payment/domain"
	"my_project/internal/payment/usecase"
	"net/http"

	"github.com/labstack/echo/v4"
)

type PaymentHandler struct {
	usecase usecase.PaymentUsecase
}

func NewPaymentHandler(u usecase.PaymentUsecase) *PaymentHandler {
	return &PaymentHandler{
		usecase: u,
	}
}

func (h *PaymentHandler) Bind(e *echo.Group) {
	e.POST("/checkout-session", h.CreateCheckoutSessionHandler, middleware.CookieSessionMiddleware())
	e.POST("/webhook", h.HandleWebhook)
}

func (h *PaymentHandler) CreateCheckoutSessionHandler(c echo.Context) error {
	var req usecase.CreateCheckoutSessionInput
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request format"})
	}

	userID, ok := c.Get("user_id").(string)
	if !ok || userID == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
	}

	userEmail, ok := c.Get("email").(string)
	if !ok || userEmail == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
	}
	ctx := c.Request().Context()
	output, err := h.usecase.CreateCheckoutSession(ctx, userID, userEmail, req)
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrInvalidPlan):
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid subscription plan"})
		case errors.Is(err, domain.ErrUserAlreadySubscribed):
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "User already has an active subscription"})
		default:
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
		}
	}

	return c.JSON(http.StatusOK, output)
}

func (h *PaymentHandler) HandleWebhook(c echo.Context) error {
	return h.usecase.HandleWebhook(c)
}
