package client

import (
	"strconv"

	"github.com/stripe/stripe-go/v84"
	"github.com/stripe/stripe-go/v84/checkout/session"
	"github.com/stripe/stripe-go/v84/webhook"
)

type Provider interface {
	CreateCheckoutSession(email, priceID, userID, plan string, quantity int) (*stripe.CheckoutSession, error)
	ConstructEvent(body []byte, signature string) (stripe.Event, error)
}

type stripeProvider struct {
	webhookSecret string
	appUrl        string
}

type StripeConfig struct {
	SecretKey     string
	WebhookSecret string
	AppUrl        string
}

func NewStripeProvider(config StripeConfig) (Provider, error) {
	stripe.Key = config.SecretKey
	appUrl := config.AppUrl
	return &stripeProvider{
		webhookSecret: config.WebhookSecret,
		appUrl:        appUrl,
	}, nil
}

func (s *stripeProvider) CreateCheckoutSession(email, priceID, userID, plan string, quantity int) (*stripe.CheckoutSession, error) {
	params := &stripe.CheckoutSessionParams{
		PaymentMethodTypes: stripe.StringSlice([]string{"card"}),
		Mode:               stripe.String("subscription"),
		LineItems: []*stripe.CheckoutSessionLineItemParams{
			{
				Price:    stripe.String(priceID),
				Quantity: stripe.Int64(int64(quantity)),
			},
		},
		SuccessURL:    stripe.String(s.appUrl + "/payment/success?session_id={CHECKOUT_SESSION_ID}"),
		CancelURL:     stripe.String(s.appUrl + "/payment/cancel"),
		CustomerEmail: stripe.String(email),
		Metadata: map[string]string{
			"user_id":  userID,
			"plan":     plan,
			"quantity": strconv.Itoa(quantity),
		},
	}

	return session.New(params)
}

func (s *stripeProvider) ConstructEvent(body []byte, signature string) (stripe.Event, error) {
	return webhook.ConstructEventWithOptions(
		body,
		signature,
		s.webhookSecret,
		webhook.ConstructEventOptions{IgnoreAPIVersionMismatch: true},
	)
}
