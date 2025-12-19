package usecase

import (
	"context"
	"errors"
	"fmt"
	"io"
	"my_project/internal/payment/domain"
	"my_project/internal/payment/repository"
	"my_project/pkg/logger"
	"net/http"
	"os"
	"strconv"

	"github.com/labstack/echo/v4"
	"github.com/stripe/stripe-go/v84"
	"github.com/stripe/stripe-go/v84/checkout/session"
	"github.com/stripe/stripe-go/v84/webhook"
)

type paymentService struct {
	subscriptionRepo repository.SubscriptionRepository
	appUrl           string
	webhookSecret    string
}

func NewPaymentUsecase(subscriptionRepo repository.SubscriptionRepository) PaymentUsecase {
	if key := os.Getenv("STRIPE_SECRET_KEY"); key != "" {
		stripe.Key = key
	}

	appUrl := os.Getenv("APP_URL")
	if appUrl == "" {
		appUrl = "http://localhost:3000"
	}

	return &paymentService{
		subscriptionRepo: subscriptionRepo,
		appUrl:           appUrl,
		webhookSecret:    os.Getenv("STRIPE_WEBHOOK_SECRET"),
	}
}

func (p *paymentService) CreateCheckoutSession(ctx context.Context, userID, email string, input CreateCheckoutSessionInput) (CreateCheckoutSessionOutput, error) {
	if !domain.IsValidPlan(input.Plan) {
		return CreateCheckoutSessionOutput{}, domain.ErrInvalidPlan
	}

	existingSub, err := p.subscriptionRepo.GetSubscriptionByUserID(ctx, userID)
	if err != nil && !errors.Is(err, domain.ErrSubscriptionNotFound) {
		return CreateCheckoutSessionOutput{}, fmt.Errorf("failed to check existing subscription: %w", err)
	}

	if existingSub != nil && existingSub.IsActive() {
		return CreateCheckoutSessionOutput{}, domain.ErrUserAlreadySubscribed
	}

	var priceID string
	switch input.Plan {
	case domain.PlanBusiness:
		priceID = os.Getenv("STRIPE_PRICE_BUSINESS_ID")
	case domain.PlanProfessional:
		priceID = os.Getenv("STRIPE_PRICE_PROFESSIONAL_ID")
	default:
		return CreateCheckoutSessionOutput{}, domain.ErrInvalidPlan
	}

	if priceID == "" {
		logger.Error("missing price ID for plan", map[string]any{
			"plan": input.Plan,
		})
		return CreateCheckoutSessionOutput{}, domain.ErrInvalidPlan
	}

	params := &stripe.CheckoutSessionParams{
		PaymentMethodTypes: stripe.StringSlice([]string{"card"}),
		Mode:               stripe.String("subscription"),
		LineItems: []*stripe.CheckoutSessionLineItemParams{
			{
				Price:    stripe.String(priceID),
				Quantity: stripe.Int64(int64(input.Quantity)),
			},
		},
		SuccessURL:    stripe.String(p.appUrl + "/payment/success?session_id={CHECKOUT_SESSION_ID}"),
		CancelURL:     stripe.String(p.appUrl + "/payment/cancel"),
		CustomerEmail: stripe.String(email),
		Metadata: map[string]string{
			"user_id":  userID,
			"plan":     string(input.Plan),
			"quantity": strconv.Itoa(input.Quantity),
		},
	}

	sess, err := session.New(params)
	if err != nil {
		logger.Error("failed to create Stripe checkout session", map[string]interface{}{
			"user_id": userID,
			"plan":    input.Plan,
			"error":   err.Error(),
		})
		return CreateCheckoutSessionOutput{}, fmt.Errorf("failed to create checkout session")
	}

	return CreateCheckoutSessionOutput{
		SessionID: sess.ID,
		URL:       sess.URL,
	}, nil
}

func (p *paymentService) HandleWebhook(c echo.Context) error {
	if p.webhookSecret == "" {
		logger.Error("webhook secret not configured", nil)
		return c.NoContent(http.StatusServiceUnavailable)
	}

	body, err := io.ReadAll(c.Request().Body)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}

	event, err := webhook.ConstructEventWithOptions(
		body,
		c.Request().Header.Get("Stripe-Signature"),
		p.webhookSecret,
		webhook.ConstructEventOptions{IgnoreAPIVersionMismatch: true},
	)
	if err != nil {
		logger.Error("invalid webhook signature", map[string]interface{}{
			"error": err.Error(),
		})
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid webhook signature"})
	}

	ctx := c.Request().Context()
	if err := p.processWebhookEvent(ctx, event); err != nil {
		logger.Error("webhook handler failed", map[string]interface{}{
			"event_type": event.Type,
			"event_id":   event.ID,
			"error":      err.Error(),
		})
		return c.NoContent(http.StatusInternalServerError)
	}

	return c.NoContent(http.StatusOK)
}

func (p *paymentService) processWebhookEvent(ctx context.Context, event stripe.Event) error {
	switch event.Type {
	case "checkout.session.completed":
		return p.handleCheckoutSessionCompleted(ctx, event)
	case "invoice.payment_succeeded":
		return p.handleInvoicePaymentSucceeded(ctx, event)
	case "invoice.payment_failed":
		return p.handleInvoicePaymentFailed(ctx, event)
	case "customer.subscription.created":
		return p.handleSubscriptionCreated(ctx, event)
	case "customer.subscription.updated":
		return p.handleSubscriptionUpdated(ctx, event)
	case "customer.subscription.deleted":
		return p.handleSubscriptionDeleted(ctx, event)
	default:
		return nil
	}
}

