package usecase

import (
	"context"
	"encoding/json"
	"fmt"
	"my_project/internal/payment/domain"
	"my_project/internal/payment/repository"
	"my_project/pkg/logger"
	"time"

	"github.com/stripe/stripe-go/v84"
)

type WebhookService struct {
	subscriptionRepo repository.SubscriptionRepository
	config           Config
}

func NewWebhookService(subscriptionRepo repository.SubscriptionRepository, config Config) *WebhookService {
	return &WebhookService{
		subscriptionRepo: subscriptionRepo,
		config:           config,
	}
}

func (ws *WebhookService) ProcessEvent(ctx context.Context, event stripe.Event) error {
	switch event.Type {
	case "checkout.session.completed":
		return ws.handleCheckoutSessionCompleted(ctx, event)
	case "invoice.payment_succeeded":
		return ws.handleInvoicePaymentSucceeded(ctx, event)
	case "invoice.payment_failed":
		return ws.handleInvoicePaymentFailed(ctx, event)
	case "customer.subscription.created", "customer.subscription.updated":
		return ws.handleSubscriptionUpdated(ctx, event)
	case "customer.subscription.deleted":
		return ws.handleSubscriptionDeleted(ctx, event)
	default:
		return nil
	}
}

func (ws *WebhookService) handleCheckoutSessionCompleted(ctx context.Context, event stripe.Event) error {
	var session stripe.CheckoutSession
	if err := json.Unmarshal(event.Data.Raw, &session); err != nil {
		return fmt.Errorf("failed to unmarshal checkout session: %w", err)
	}

	meta, err := newSubscriptionMetadata(session.Metadata)
	if err != nil {
		return err
	}

	sub := meta.toSubscription(session.Customer.ID)
	if err := ws.subscriptionRepo.CreateSubscription(ctx, sub); err != nil {
		logger.Error(fmt.Sprintf("failed to create subscription from checkout. user_id: %s, cus_id: %s, err: %s", sub.UserID, *sub.CusID, err.Error()))
		existing, getErr := ws.subscriptionRepo.GetSubscriptionByUserID(ctx, sub.UserID.String())
		if getErr != nil {
			return fmt.Errorf("failed to get existing subscription: %w", getErr)
		}
		existing.CusID = sub.CusID
		existing.Status = domain.StatusPending
		existing.UpdatedAt = time.Now().Unix()
		if updateErr := ws.subscriptionRepo.UpdateSubscription(ctx, existing); updateErr != nil {
			return fmt.Errorf("failed to update existing subscription: %w", updateErr)
		}
	}

	return nil
}

func (ws *WebhookService) handleInvoicePaymentSucceeded(ctx context.Context, event stripe.Event) error {
	var invoice stripe.Invoice
	if err := json.Unmarshal(event.Data.Raw, &invoice); err != nil {
		return fmt.Errorf("failed to unmarshal invoice: %w", err)
	}
	if invoice.Customer == nil || len(invoice.Lines.Data) == 0 || invoice.Lines.Data[0].Subscription == nil {
		return fmt.Errorf("invalid invoice data")
	}

	subID := invoice.Lines.Data[0].Subscription.ID
	updater := func(sub *domain.Subscription) {
		sub.Status = domain.StatusActive
		sub.Paid = true
		if invoice.Lines.Data[0].Period != nil {
			sub.CurrentPeriodStart = invoice.Lines.Data[0].Period.Start
			sub.CurrentPeriodEnd = invoice.Lines.Data[0].Period.End
		}
	}

	return ws.updateSubscription(ctx, subID, invoice.Customer.ID, updater)
}

func (ws *WebhookService) handleInvoicePaymentFailed(ctx context.Context, event stripe.Event) error {
	var invoice stripe.Invoice
	if err := json.Unmarshal(event.Data.Raw, &invoice); err != nil {
		return fmt.Errorf("failed to unmarshal invoice: %w", err)
	}
	if invoice.Customer == nil || len(invoice.Lines.Data) == 0 || invoice.Lines.Data[0].Subscription == nil {
		return fmt.Errorf("invalid invoice data")
	}

	subID := invoice.Lines.Data[0].Subscription.ID
	updater := func(sub *domain.Subscription) {
		sub.Status = domain.StatusPastDue
	}

	err := ws.updateSubscription(ctx, subID, invoice.Customer.ID, updater)
	if err != nil {
		logger.Error(fmt.Sprintf("invoice payment failed. sub_id: %s, customer_id: %s, amount: %d", subID, invoice.Customer.ID, invoice.AmountDue))
	}
	return err
}

func (ws *WebhookService) handleSubscriptionUpdated(ctx context.Context, event stripe.Event) error {
	var stripeSub stripe.Subscription
	if err := json.Unmarshal(event.Data.Raw, &stripeSub); err != nil {
		return fmt.Errorf("failed to unmarshal subscription: %w", err)
	}

	updater := func(sub *domain.Subscription) {
		ws.updateSubscriptionDetails(sub, &stripeSub)
	}

	return ws.updateSubscription(ctx, stripeSub.ID, stripeSub.Customer.ID, updater)
}

func (ws *WebhookService) handleSubscriptionDeleted(ctx context.Context, event stripe.Event) error {
	var stripeSub stripe.Subscription
	if err := json.Unmarshal(event.Data.Raw, &stripeSub); err != nil {
		return fmt.Errorf("failed to unmarshal subscription: %w", err)
	}

	updater := func(sub *domain.Subscription) {
		sub.Status = domain.StatusCanceled
		sub.CancelAtPeriodEnd = true
	}

	return ws.updateSubscription(ctx, stripeSub.ID, stripeSub.Customer.ID, updater)
}

func (ws *WebhookService) updateSubscription(ctx context.Context, subID, cusID string, updater func(*domain.Subscription)) error {
	sub, err := ws.getSubscription(ctx, subID, cusID)
	if err != nil {
		return err
	}

	updater(sub)
	sub.UpdatedAt = time.Now().Unix()

	if err := ws.subscriptionRepo.UpdateSubscription(ctx, sub); err != nil {
		return fmt.Errorf("failed to update subscription: %w", err)
	}
	return nil
}

func (ws *WebhookService) getSubscription(ctx context.Context, subID, cusID string) (*domain.Subscription, error) {
	sub, err := ws.subscriptionRepo.GetSubscriptionBySubID(ctx, subID)
	if err != nil {
		sub, err = ws.subscriptionRepo.GetSubscriptionByCustomerID(ctx, cusID)
		if err != nil {
			return nil, fmt.Errorf("subscription not found for subID %s or cusID %s", subID, cusID)
		}
		sub.SubID = &subID
	}
	return sub, nil
}

func (ws *WebhookService) updateSubscriptionDetails(sub *domain.Subscription, stripeSub *stripe.Subscription) {
	sub.Status = domain.SubscriptionStatus(stripeSub.Status)
	sub.CurrentPeriodStart = stripeSub.StartDate
	sub.CurrentPeriodEnd = stripeSub.EndedAt
	sub.CancelAtPeriodEnd = stripeSub.CancelAtPeriodEnd

	if len(stripeSub.Items.Data) > 0 {
		item := stripeSub.Items.Data[0]
		sub.LicenseCount = int(item.Quantity)
		if item.Price != nil {
			sub.Plan = ws.planFromPriceID(item.Price.ID)
		}
	}
}

func (ws *WebhookService) planFromPriceID(priceID string) domain.SubscriptionPlan {
	switch priceID {
	case ws.config.PriceBusinessID:
		return domain.PlanBusiness
	case ws.config.PriceProID:
		return domain.PlanProfessional
	default:
		return domain.PlanBusiness
	}
}
