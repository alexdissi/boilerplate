package usecase

import (
	"context"
	"errors"
	"fmt"
	"io"
	"my_project/internal/payment/client"
	"my_project/internal/payment/domain"
	"my_project/internal/payment/repository"
	"my_project/pkg/logger"
	"net/http"

	gostripe "github.com/stripe/stripe-go/v84"
)

type paymentService struct {
	subscriptionRepo repository.SubscriptionRepository
	provider         client.Provider
	config           Config
}

type Config struct {
	PriceProID      string
	PriceBusinessID string
}

func NewPaymentUsecase(subscriptionRepo repository.SubscriptionRepository, provider client.Provider, config Config) PaymentUsecase {
	return &paymentService{
		subscriptionRepo: subscriptionRepo,
		provider:         provider,
		config:           config,
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

	if existingSub != nil && existingSub.IsActive() && existingSub.Plan != domain.PlanFree {
		return CreateCheckoutSessionOutput{}, domain.ErrUserAlreadySubscribed
	}

	var priceID string
	switch input.Plan {
	case domain.PlanBusiness:
		priceID = p.config.PriceBusinessID
	case domain.PlanProfessional:
		priceID = p.config.PriceProID
	default:
		return CreateCheckoutSessionOutput{}, domain.ErrInvalidPlan
	}

	if priceID == "" {
		logger.Error("missing price ID for plan", map[string]any{
			"plan": input.Plan,
		})
		return CreateCheckoutSessionOutput{}, domain.ErrInvalidPlan
	}

	sess, err := p.provider.CreateCheckoutSession(email, priceID, userID, string(input.Plan), input.Quantity)
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

func (p *paymentService) CreatePortalSession(ctx context.Context, userID string) (CreatePortalSessionOutput, error) {
	sub, err := p.subscriptionRepo.GetSubscriptionByUserID(ctx, userID)
	if err != nil {
		return CreatePortalSessionOutput{}, fmt.Errorf("failed to get subscription: %w", err)
	}

	if sub == nil || sub.CusID == nil || *sub.CusID == "" {
		return CreatePortalSessionOutput{}, domain.ErrSubscriptionNotFound
	}

	portalSession, err := p.provider.CreatePortalSession(*sub.CusID)
	if err != nil {
		logger.Error("failed to create portal session", map[string]interface{}{
			"user_id":     userID,
			"customer_id": *sub.CusID,
			"error":       err.Error(),
		})
		return CreatePortalSessionOutput{}, fmt.Errorf("failed to create portal session")
	}

	return CreatePortalSessionOutput{
		URL: portalSession.URL,
	}, nil
}

func (p *paymentService) HandleWebhook(r *http.Request) error {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("%w: invalid request body", domain.ErrWebhook)
	}

	event, err := p.provider.ConstructEvent(body, r.Header.Get("Stripe-Signature"))
	if err != nil {
		logger.Error("invalid webhook signature", map[string]interface{}{
			"error": err.Error(),
		})
		return fmt.Errorf("%w: invalid signature", domain.ErrWebhook)
	}

	ctx := r.Context()
	if err := p.processWebhookEvent(ctx, event); err != nil {
		logger.Error("webhook handler failed", map[string]interface{}{
			"event_type": event.Type,
			"event_id":   event.ID,
			"error":      err.Error(),
		})
		return fmt.Errorf("%w: failed to process event", domain.ErrWebhook)
	}

	return nil
}

func (p *paymentService) processWebhookEvent(ctx context.Context, event gostripe.Event) error {
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
