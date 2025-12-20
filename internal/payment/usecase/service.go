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
)

type paymentService struct {
	subscriptionRepo repository.SubscriptionRepository
	provider         client.Provider
	webhookService   *WebhookService
	config           Config
}

type Config struct {
	PriceProID      string
	PriceBusinessID string
}

func NewPaymentUsecase(
	subscriptionRepo repository.SubscriptionRepository,
	provider client.Provider,
	config Config,
) PaymentUsecase {
	webhookService := NewWebhookService(subscriptionRepo, config)
	return &paymentService{
		subscriptionRepo: subscriptionRepo,
		provider:         provider,
		webhookService:   webhookService,
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

	priceID, err := p.priceIDFromPlan(input.Plan)
	if err != nil {
		return CreateCheckoutSessionOutput{}, err
	}

	sess, err := p.provider.CreateCheckoutSession(email, priceID, userID, string(input.Plan), input.Quantity)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to create Stripe checkout session. user_id: %s, plan: %s, err: %s", userID, input.Plan, err.Error()))
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
		logger.Error(fmt.Sprintf("failed to create portal session. user_id: %s, customer_id: %s, err: %s", userID, *sub.CusID, err.Error()))
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
		logger.Error(fmt.Sprintf("invalid webhook signature. err: %s", err.Error()))
		return fmt.Errorf("%w: invalid signature", domain.ErrWebhook)
	}

	if err := p.webhookService.ProcessEvent(r.Context(), event); err != nil {
		logger.Error(fmt.Sprintf("failed to process webhook event. type: %s, err: %s", event.Type, err.Error()))
		return fmt.Errorf("%w: failed to process event", domain.ErrWebhook)
	}

	return nil
}

func (p *paymentService) priceIDFromPlan(plan domain.SubscriptionPlan) (string, error) {
	var priceID string
	switch plan {
	case domain.PlanBusiness:
		priceID = p.config.PriceBusinessID
	case domain.PlanProfessional:
		priceID = p.config.PriceProID
	default:
		return "", domain.ErrInvalidPlan
	}
	if priceID == "" {
		logger.Error(fmt.Sprintf("missing price ID for plan: %s", plan))
		return "", domain.ErrInvalidPlan
	}
	return priceID, nil
}
