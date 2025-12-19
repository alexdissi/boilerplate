package usecase

import (
	"context"
	"encoding/json"
	"fmt"
	"my_project/internal/payment/domain"
	"my_project/pkg/logger"
	"os"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/stripe/stripe-go/v84"
)

func (p *paymentService) handleCheckoutSessionCompleted(ctx context.Context, event stripe.Event) error {
	var sess stripe.CheckoutSession
	if err := json.Unmarshal(event.Data.Raw, &sess); err != nil {
		return fmt.Errorf("invalid checkout session payload: %w", err)
	}

	if sess.Customer == nil {
		return fmt.Errorf("missing customer in checkout session")
	}

	userID, ok := sess.Metadata["user_id"]
	if !ok {
		return fmt.Errorf("missing user_id in checkout session metadata")
	}

	plan, ok := sess.Metadata["plan"]
	if !ok {
		return fmt.Errorf("missing plan in checkout session metadata")
	}

	quantity, err := extractQuantityFromMetadata(sess.Metadata)
	if err != nil {
		return fmt.Errorf("invalid quantity in metadata: %w", err)
	}

	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return fmt.Errorf("invalid user ID format: %w", err)
	}

	subscription := &domain.Subscription{
		UserID:             userUUID,
		Plan:               domain.SubscriptionPlan(plan),
		CusID:              sess.Customer.ID,
		LicenseCount:       quantity,
		Status:             domain.StatusPending,
		Paid:               false,
		CurrentPeriodStart: time.Now().Unix(),
		CurrentPeriodEnd:   time.Now().Unix(),
		CancelAtPeriodEnd:  false,
		CreatedAt:          time.Now().Unix(),
		UpdatedAt:          time.Now().Unix(),
	}

	if createErr := p.subscriptionRepo.CreateSubscription(ctx, subscription); createErr != nil {
		if createErr.Error() == "pq: duplicate key value violates unique constraint \"subscriptions_user_id_key\"" ||
			createErr.Error() == "UNIQUE constraint failed: subscriptions.user_id" {
			return p.updateExistingSubscription(ctx, userID, sess.Customer.ID)
		}
		return fmt.Errorf("failed to create subscription: %w", createErr)
	}

	logger.Info("checkout session completed", map[string]any{
		"user_id":     userID,
		"plan":        plan,
		"customer_id": sess.Customer.ID,
	})

	return nil
}

func (p *paymentService) handleInvoicePaymentSucceeded(ctx context.Context, event stripe.Event) error {
	invoice, err := extractInvoice(event)
	if err != nil {
		return err
	}

	if invoice.Customer == nil {
		return fmt.Errorf("missing customer in invoice")
	}

	subscription, err := p.findSubscriptionForInvoice(ctx, invoice)
	if err != nil {
		return fmt.Errorf("failed to find subscription for invoice: %w", err)
	}

	subscription.Status = domain.StatusActive
	subscription.Paid = true
	subscription.UpdatedAt = time.Now().Unix()

	if len(invoice.Lines.Data) > 0 {
		if invoice.Lines.Data[0].Period != nil {
			subscription.CurrentPeriodStart = invoice.Lines.Data[0].Period.Start
			subscription.CurrentPeriodEnd = invoice.Lines.Data[0].Period.End
		}

		if invoice.Lines.Data[0].Subscription != nil && subscription.SubID == nil {
			subscription.SubID = &invoice.Lines.Data[0].Subscription.ID
			logger.Info("updated subscription ID from invoice", map[string]any{
				"user_id": subscription.UserID,
				"sub_id":  invoice.Lines.Data[0].Subscription.ID,
			})
		}
	}

	if err := p.subscriptionRepo.UpdateSubscription(ctx, subscription); err != nil {
		return fmt.Errorf("failed to update subscription after payment: %w", err)
	}

	logger.Info("invoice payment succeeded", map[string]any{
		"user_id":     subscription.UserID,
		"plan":        subscription.Plan,
		"amount":      invoice.AmountPaid,
		"currency":    invoice.Currency,
		"customer_id": invoice.Customer.ID,
	})

	return nil
}

func (p *paymentService) handleInvoicePaymentFailed(ctx context.Context, event stripe.Event) error {
	invoice, err := extractInvoice(event)
	if err != nil {
		return err
	}

	if invoice.Customer == nil {
		return fmt.Errorf("missing customer in invoice")
	}

	subscription, err := p.findSubscriptionForInvoice(ctx, invoice)
	if err != nil {
		return fmt.Errorf("failed to find subscription for failed invoice: %w", err)
	}

	subscription.Status = domain.StatusPastDue
	subscription.UpdatedAt = time.Now().Unix()

	if err := p.subscriptionRepo.UpdateSubscription(ctx, subscription); err != nil {
		return fmt.Errorf("failed to update subscription after failed payment: %w", err)
	}

	logger.Error("invoice payment failed", map[string]any{
		"user_id":     subscription.UserID,
		"customer_id": invoice.Customer.ID,
		"amount":      invoice.AmountDue,
	})

	return nil
}

func (p *paymentService) handleSubscriptionCreated(ctx context.Context, event stripe.Event) error {
	sub, err := extractSubscription(event)
	if err != nil {
		return err
	}

	if sub.Customer == nil {
		return fmt.Errorf("missing customer in subscription")
	}

	logger.Info("subscription created webhook received", map[string]any{
		"sub_id":      sub.ID,
		"customer_id": sub.Customer.ID,
		"metadata":    sub.Metadata,
	})

	existing, err := p.subscriptionRepo.GetSubscriptionByCustomerID(ctx, sub.Customer.ID)
	if err == nil && existing != nil {
		logger.Info("found subscription by customer ID, updating", map[string]any{
			"sub_id":  sub.ID,
			"user_id": existing.UserID,
		})
		return p.updateExistingFromStripeSubscription(ctx, existing, sub)
	}

	if sub.Metadata != nil {
		if userID, ok := sub.Metadata["user_id"]; ok {
			existing, err = p.subscriptionRepo.GetSubscriptionByUserID(ctx, userID)
			if err == nil && existing != nil {
				logger.Info("found subscription by user ID, updating", map[string]any{
					"sub_id":  sub.ID,
					"user_id": userID,
				})
				return p.updateExistingFromStripeSubscription(ctx, existing, sub)
			}
		}
	}

	logger.Info("subscription created without metadata or no existing subscription found", map[string]any{
		"sub_id":      sub.ID,
		"customer_id": sub.Customer.ID,
		"metadata":    sub.Metadata,
	})

	return nil
}

func (p *paymentService) handleSubscriptionUpdated(ctx context.Context, event stripe.Event) error {
	sub, err := extractSubscription(event)
	if err != nil {
		return err
	}

	existing, err := p.subscriptionRepo.GetSubscriptionBySubID(ctx, sub.ID)
	if err != nil {
		return fmt.Errorf("subscription not found: %w", err)
	}

	return p.updateExistingFromStripeSubscription(ctx, existing, sub)
}

func (p *paymentService) handleSubscriptionDeleted(ctx context.Context, event stripe.Event) error {
	sub, err := extractSubscription(event)
	if err != nil {
		return err
	}

	existing, err := p.subscriptionRepo.GetSubscriptionBySubID(ctx, sub.ID)
	if err != nil {
		return fmt.Errorf("subscription not found for deletion: %w", err)
	}

	existing.Status = domain.StatusCanceled
	existing.CancelAtPeriodEnd = true
	existing.UpdatedAt = time.Now().Unix()

	if err := p.subscriptionRepo.UpdateSubscription(ctx, existing); err != nil {
		return fmt.Errorf("failed to cancel subscription: %w", err)
	}

	logger.Info("subscription canceled", map[string]any{
		"user_id": existing.UserID,
		"sub_id":  sub.ID,
	})

	return nil
}

func extractQuantityFromMetadata(metadata map[string]string) (int, error) {
	quantityStr, ok := metadata["quantity"]
	if !ok {
		return 1, nil
	}

	quantity, err := strconv.Atoi(quantityStr)
	if err != nil || quantity < 1 {
		return 1, fmt.Errorf("invalid quantity: %s", quantityStr)
	}

	if quantity > 100 {
		return 100, nil
	}

	return quantity, nil
}

func extractInvoice(event stripe.Event) (*stripe.Invoice, error) {
	var invoice stripe.Invoice
	if err := json.Unmarshal(event.Data.Raw, &invoice); err != nil {
		return nil, fmt.Errorf("invalid invoice payload: %w", err)
	}
	return &invoice, nil
}

func extractSubscription(event stripe.Event) (*stripe.Subscription, error) {
	var sub stripe.Subscription
	if err := json.Unmarshal(event.Data.Raw, &sub); err != nil {
		return nil, fmt.Errorf("invalid subscription payload: %w", err)
	}
	return &sub, nil
}

func (p *paymentService) findSubscriptionForInvoice(ctx context.Context, invoice *stripe.Invoice) (*domain.Subscription, error) {
	if len(invoice.Lines.Data) == 0 || invoice.Lines.Data[0].Subscription == nil {
		return nil, fmt.Errorf("no subscription in invoice")
	}

	subID := invoice.Lines.Data[0].Subscription.ID
	subscription, err := p.subscriptionRepo.GetSubscriptionBySubID(ctx, subID)
	if err == nil {
		return subscription, nil
	}

	return p.subscriptionRepo.GetSubscriptionByCustomerID(ctx, invoice.Customer.ID)
}

func (p *paymentService) updateExistingSubscription(ctx context.Context, userID, customerID string) error {
	existing, err := p.subscriptionRepo.GetSubscriptionByUserID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to find existing subscription: %w", err)
	}

	existing.CusID = customerID
	existing.Status = domain.StatusPending
	existing.UpdatedAt = time.Now().Unix()

	return p.subscriptionRepo.UpdateSubscription(ctx, existing)
}

func (p *paymentService) updateExistingFromStripeSubscription(ctx context.Context, existing *domain.Subscription, sub *stripe.Subscription) error {
	existing.SubID = &sub.ID
	existing.Status = domain.SubscriptionStatus(sub.Status)
	existing.CurrentPeriodStart = sub.StartDate
	existing.CurrentPeriodEnd = sub.EndedAt
	existing.CancelAtPeriodEnd = sub.CancelAtPeriodEnd
	existing.UpdatedAt = time.Now().Unix()

	if len(sub.Items.Data) > 0 {
		existing.LicenseCount = int(sub.Items.Data[0].Quantity)
		if sub.Items.Data[0].Price != nil {
			priceID := sub.Items.Data[0].Price.ID
			switch priceID {
			case os.Getenv("STRIPE_PRICE_BUSINESS_ID"):
				existing.Plan = domain.PlanBusiness
			case os.Getenv("STRIPE_PRICE_PROFESSIONAL_ID"):
				existing.Plan = domain.PlanProfessional
			default:
				existing.Plan = domain.PlanBusiness
			}
		}
	}

	return p.subscriptionRepo.UpdateSubscription(ctx, existing)
}

func (p *paymentService) createFromSubscriptionMetadata(ctx context.Context, sub *stripe.Subscription) error {
	if sub.Metadata == nil {
		return fmt.Errorf("no metadata in subscription")
	}

	userID, ok := sub.Metadata["user_id"]
	if !ok {
		return fmt.Errorf("missing user_id in subscription metadata")
	}

	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return fmt.Errorf("invalid user ID format: %w", err)
	}

	plan := domain.SubscriptionPlan(sub.Metadata["plan"])
	quantity, _ := extractQuantityFromMetadata(sub.Metadata)

	subscription := &domain.Subscription{
		UserID:             userUUID,
		Plan:               plan,
		SubID:              &sub.ID,
		CusID:              sub.Customer.ID,
		LicenseCount:       quantity,
		Status:             domain.SubscriptionStatus(sub.Status),
		Paid:               sub.Status == "active" || sub.Status == "trialing",
		CurrentPeriodStart: sub.StartDate,
		CurrentPeriodEnd:   sub.EndedAt,
		CancelAtPeriodEnd:  sub.CancelAtPeriodEnd,
		CreatedAt:          time.Now().Unix(),
		UpdatedAt:          time.Now().Unix(),
	}

	if len(sub.Items.Data) > 0 && sub.Items.Data[0].Price != nil {
		priceID := sub.Items.Data[0].Price.ID
		switch priceID {
		case os.Getenv("STRIPE_PRICE_BUSINESS_ID"):
			subscription.Plan = domain.PlanBusiness
		case os.Getenv("STRIPE_PRICE_PROFESSIONAL_ID"):
			subscription.Plan = domain.PlanProfessional
		default:
			subscription.Plan = domain.PlanBusiness
		}
	}

	return p.subscriptionRepo.CreateSubscription(ctx, subscription)
}
