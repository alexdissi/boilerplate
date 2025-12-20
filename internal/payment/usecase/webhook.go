package usecase

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"my_project/internal/payment/domain"
	"my_project/pkg/logger"
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

	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return fmt.Errorf("invalid user ID format: %w", err)
	}

	quantityStr, ok := sess.Metadata["quantity"]
	var quantity int = 1
	if ok {
		q, err := strconv.Atoi(quantityStr)
		if err == nil && q > 0 {
			if q > 100 {
				quantity = 100
			} else {
				quantity = q
			}
		}
	}

	subscription := &domain.Subscription{
		UserID:             userUUID,
		Plan:               domain.SubscriptionPlan(sess.Metadata["plan"]),
		CusID:              &sess.Customer.ID,
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
		existing, err := p.subscriptionRepo.GetSubscriptionByUserID(ctx, subscription.UserID.String())
		if err != nil {
			if errors.Is(err, domain.ErrSubscriptionNotFound) {
				return fmt.Errorf("failed to create subscription and no existing subscription found: %w", createErr)
			}
			return fmt.Errorf("database error while looking up existing subscription: %w", err)
		}

		existing.CusID = subscription.CusID
		existing.Status = domain.StatusPending
		existing.UpdatedAt = time.Now().Unix()
		if updateErr := p.subscriptionRepo.UpdateSubscription(ctx, existing); updateErr != nil {
			return fmt.Errorf("failed to update existing subscription after checkout: %w", updateErr)
		}
	}
	return nil
}

func (p *paymentService) handleInvoicePaymentSucceeded(ctx context.Context, event stripe.Event) error {
	var invoice stripe.Invoice
	if err := json.Unmarshal(event.Data.Raw, &invoice); err != nil {
		return fmt.Errorf("invalid invoice payload: %w", err)
	}

	if invoice.Customer == nil {
		return fmt.Errorf("missing customer in invoice")
	}

	if len(invoice.Lines.Data) == 0 || invoice.Lines.Data[0].Subscription == nil {
		return fmt.Errorf("no subscription in invoice")
	}
	subID := invoice.Lines.Data[0].Subscription.ID
	subscription, err := p.subscriptionRepo.GetSubscriptionBySubID(ctx, subID)
	if err != nil {
		subscription, err = p.subscriptionRepo.GetSubscriptionByCustomerID(ctx, invoice.Customer.ID)
		if err != nil {
			logger.Error("failed to find subscription for invoice by customer ID", map[string]any{
				"sub_id":      subID,
				"customer_id": invoice.Customer.ID,
				"error":       err.Error(),
			})
			return nil
		}

		subscription.SubID = &subID
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
		}
	}

	if err := p.subscriptionRepo.UpdateSubscription(ctx, subscription); err != nil {
		return fmt.Errorf("failed to update subscription after payment: %w", err)
	}

	return nil
}

func (p *paymentService) handleInvoicePaymentFailed(ctx context.Context, event stripe.Event) error {
	var invoice stripe.Invoice
	if err := json.Unmarshal(event.Data.Raw, &invoice); err != nil {
		return fmt.Errorf("invalid invoice payload: %w", err)
	}

	if invoice.Customer == nil {
		return fmt.Errorf("missing customer in invoice")
	}

	if len(invoice.Lines.Data) == 0 || invoice.Lines.Data[0].Subscription == nil {
		return fmt.Errorf("no subscription in invoice")
	}
	subID := invoice.Lines.Data[0].Subscription.ID
	subscription, err := p.subscriptionRepo.GetSubscriptionBySubID(ctx, subID)
	if err != nil {
		subscription, err = p.subscriptionRepo.GetSubscriptionByCustomerID(ctx, invoice.Customer.ID)
		if err != nil {
			logger.Error("failed to find subscription for failed invoice by customer ID", map[string]any{
				"sub_id":      subID,
				"customer_id": invoice.Customer.ID,
				"error":       err.Error(),
			})

			return nil
		}

		subscription.SubID = &subID
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
	var sub stripe.Subscription
	if err := json.Unmarshal(event.Data.Raw, &sub); err != nil {
		return fmt.Errorf("invalid subscription payload: %w", err)
	}

	if sub.Customer == nil {
		return fmt.Errorf("missing customer in subscription")
	}

	existing, err := p.subscriptionRepo.GetSubscriptionByCustomerID(ctx, sub.Customer.ID)
	if err == nil && existing != nil {
		existing.SubID = &sub.ID
		existing.Status = domain.SubscriptionStatus(sub.Status)
		existing.CurrentPeriodStart = sub.StartDate
		if sub.EndedAt != 0 {
			existing.CurrentPeriodEnd = sub.EndedAt
		}
		existing.CancelAtPeriodEnd = sub.CancelAtPeriodEnd
		existing.UpdatedAt = time.Now().Unix()

		if len(sub.Items.Data) > 0 {
			item := sub.Items.Data[0]
			existing.LicenseCount = int(item.Quantity)
			if item.Price != nil {
				switch item.Price.ID {
				case p.config.PriceBusinessID:
					existing.Plan = domain.PlanBusiness
				case p.config.PriceProID:
					existing.Plan = domain.PlanProfessional
				default:
					existing.Plan = domain.PlanBusiness
				}
			}
		}
		return p.subscriptionRepo.UpdateSubscription(ctx, existing)
	}

	if sub.Metadata != nil {
		if userID, ok := sub.Metadata["user_id"]; ok {
			existing, err = p.subscriptionRepo.GetSubscriptionByUserID(ctx, userID)
			if err == nil && existing != nil {
				existing.SubID = &sub.ID
				existing.Status = domain.SubscriptionStatus(sub.Status)
				existing.CurrentPeriodStart = sub.StartDate
				if sub.EndedAt != 0 {
					existing.CurrentPeriodEnd = sub.EndedAt
				}
				existing.CancelAtPeriodEnd = sub.CancelAtPeriodEnd
				existing.UpdatedAt = time.Now().Unix()

				if len(sub.Items.Data) > 0 {
					item := sub.Items.Data[0]
					existing.LicenseCount = int(item.Quantity)
					if item.Price != nil {
						switch item.Price.ID {
						case p.config.PriceBusinessID:
							existing.Plan = domain.PlanBusiness
						case p.config.PriceProID:
							existing.Plan = domain.PlanProfessional
						default:
							existing.Plan = domain.PlanBusiness
						}
					}
				}
				return p.subscriptionRepo.UpdateSubscription(ctx, existing)
			}
		}
	}

	return nil
}

func (p *paymentService) handleSubscriptionUpdated(ctx context.Context, event stripe.Event) error {
	var sub stripe.Subscription
	if err := json.Unmarshal(event.Data.Raw, &sub); err != nil {
		return fmt.Errorf("invalid subscription payload: %w", err)
	}

	existing, err := p.subscriptionRepo.GetSubscriptionBySubID(ctx, sub.ID)
	if err != nil {
		return fmt.Errorf("subscription not found: %w", err)
	}

	existing.SubID = &sub.ID
	existing.Status = domain.SubscriptionStatus(sub.Status)
	existing.CurrentPeriodStart = sub.StartDate
	if sub.EndedAt != 0 {
		existing.CurrentPeriodEnd = sub.EndedAt
	}
	existing.CancelAtPeriodEnd = sub.CancelAtPeriodEnd
	existing.UpdatedAt = time.Now().Unix()

	if len(sub.Items.Data) > 0 {
		item := sub.Items.Data[0]
		existing.LicenseCount = int(item.Quantity)
		if item.Price != nil {
			switch item.Price.ID {
			case p.config.PriceBusinessID:
				existing.Plan = domain.PlanBusiness
			case p.config.PriceProID:
				existing.Plan = domain.PlanProfessional
			default:
				existing.Plan = domain.PlanBusiness
			}
		}
	}
	return p.subscriptionRepo.UpdateSubscription(ctx, existing)
}

func (p *paymentService) handleSubscriptionDeleted(ctx context.Context, event stripe.Event) error {
	var sub stripe.Subscription
	if err := json.Unmarshal(event.Data.Raw, &sub); err != nil {
		return fmt.Errorf("invalid subscription payload: %w", err)
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

	return nil
}
