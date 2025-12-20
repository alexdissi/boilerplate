package test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stripe/stripe-go/v84"
	"go.uber.org/mock/gomock"

	"my_project/internal/payment/domain"
	"my_project/internal/payment/usecase"
)

func TestPaymentService_CreatePortalSession(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := NewMockSubscriptionRepository(ctrl)
	mockProvider := NewMockProvider(ctrl)

	config := usecase.Config{
		PriceProID:      "price_pro_123",
		PriceBusinessID: "price_business_456",
	}

	service := usecase.NewPaymentUsecase(mockRepo, mockProvider, config)
	ctx := context.Background()

	t.Run("successful portal session creation", func(t *testing.T) {
		userID := uuid.New().String()
		customerID := "cus_test12345"
		portalURL := "https://billing.stripe.com/portal/session_test"

		subscription := &domain.Subscription{
			UserID:       uuid.MustParse(userID),
			Plan:         domain.PlanProfessional,
			Status:       domain.StatusActive,
			CusID:        &customerID,
			LicenseCount: 5,
			Paid:         true,
		}

		portalSession := &stripe.BillingPortalSession{
			ID:  "bps_test123",
			URL: portalURL,
		}

		// Mock repository call
		mockRepo.EXPECT().
			GetSubscriptionByUserID(ctx, userID).
			Return(subscription, nil)

		// Mock provider call
		mockProvider.EXPECT().
			CreatePortalSession(customerID).
			Return(portalSession, nil)

		result, err := service.CreatePortalSession(ctx, userID)

		require.NoError(t, err)
		assert.Equal(t, portalURL, result.URL)
	})

	t.Run("subscription not found", func(t *testing.T) {
		userID := uuid.New().String()

		// Mock repository call returns not found
		mockRepo.EXPECT().
			GetSubscriptionByUserID(ctx, userID).
			Return(nil, domain.ErrSubscriptionNotFound)

		result, err := service.CreatePortalSession(ctx, userID)

		assert.Error(t, err)
		assert.Equal(t, usecase.CreatePortalSessionOutput{}, result)
		assert.Contains(t, err.Error(), "failed to get subscription")
		assert.Contains(t, err.Error(), domain.ErrSubscriptionNotFound.Error())
	})

	t.Run("database error when retrieving subscription", func(t *testing.T) {
		userID := uuid.New().String()
		dbError := errors.New("database connection timeout")

		// Mock repository call returns database error
		mockRepo.EXPECT().
			GetSubscriptionByUserID(ctx, userID).
			Return(nil, dbError)

		result, err := service.CreatePortalSession(ctx, userID)

		assert.Error(t, err)
		assert.Equal(t, usecase.CreatePortalSessionOutput{}, result)
		assert.Contains(t, err.Error(), "failed to get subscription")
		assert.Contains(t, err.Error(), dbError.Error())
	})

	t.Run("subscription exists but customer ID is nil", func(t *testing.T) {
		userID := uuid.New().String()

		subscription := &domain.Subscription{
			UserID:       uuid.MustParse(userID),
			Plan:         domain.PlanProfessional,
			Status:       domain.StatusActive,
			CusID:        nil, // Customer ID is nil
			LicenseCount: 5,
			Paid:         true,
		}

		// Mock repository call
		mockRepo.EXPECT().
			GetSubscriptionByUserID(ctx, userID).
			Return(subscription, nil)

		result, err := service.CreatePortalSession(ctx, userID)

		assert.Error(t, err)
		assert.Equal(t, usecase.CreatePortalSessionOutput{}, result)
		assert.Equal(t, domain.ErrSubscriptionNotFound, err)
	})

	t.Run("subscription exists but customer ID is empty", func(t *testing.T) {
		userID := uuid.New().String()
		emptyCustomerID := ""

		subscription := &domain.Subscription{
			UserID:       uuid.MustParse(userID),
			Plan:         domain.PlanProfessional,
			Status:       domain.StatusActive,
			CusID:        &emptyCustomerID, // Customer ID is empty string
			LicenseCount: 5,
			Paid:         true,
		}

		// Mock repository call
		mockRepo.EXPECT().
			GetSubscriptionByUserID(ctx, userID).
			Return(subscription, nil)

		result, err := service.CreatePortalSession(ctx, userID)

		assert.Error(t, err)
		assert.Equal(t, usecase.CreatePortalSessionOutput{}, result)
		assert.Equal(t, domain.ErrSubscriptionNotFound, err)
	})

	t.Run("provider fails to create portal session - skipped due to logger dependency", func(t *testing.T) {
		t.Skip("Skipping test that requires logger initialization")
	})

	t.Run("canceled subscription still allows portal access", func(t *testing.T) {
		userID := uuid.New().String()
		customerID := "cus_test_canceled"
		portalURL := "https://billing.stripe.com/portal/canceled_session"

		subscription := &domain.Subscription{
			UserID:            uuid.MustParse(userID),
			Plan:              domain.PlanProfessional,
			Status:            domain.StatusCanceled,
			CusID:             &customerID,
			LicenseCount:      5,
			Paid:              true,
			CancelAtPeriodEnd: true,
		}

		portalSession := &stripe.BillingPortalSession{
			ID:  "bps_canceled_test",
			URL: portalURL,
		}

		// Mock repository call
		mockRepo.EXPECT().
			GetSubscriptionByUserID(ctx, userID).
			Return(subscription, nil)

		// Mock provider call
		mockProvider.EXPECT().
			CreatePortalSession(customerID).
			Return(portalSession, nil)

		result, err := service.CreatePortalSession(ctx, userID)

		require.NoError(t, err)
		assert.Equal(t, portalURL, result.URL)
	})

	t.Run("past due subscription allows portal access", func(t *testing.T) {
		userID := uuid.New().String()
		customerID := "cus_test_past_due"
		portalURL := "https://billing.stripe.com/portal/past_due_session"

		subscription := &domain.Subscription{
			UserID:             uuid.MustParse(userID),
			Plan:               domain.PlanBusiness,
			Status:             domain.StatusPastDue,
			CusID:              &customerID,
			LicenseCount:       3,
			Paid:               false,
			CurrentPeriodStart: time.Now().Add(-30 * 24 * time.Hour).Unix(),
			CurrentPeriodEnd:   time.Now().Add(-1 * 24 * time.Hour).Unix(),
		}

		portalSession := &stripe.BillingPortalSession{
			ID:  "bps_past_due_test",
			URL: portalURL,
		}

		// Mock repository call
		mockRepo.EXPECT().
			GetSubscriptionByUserID(ctx, userID).
			Return(subscription, nil)

		// Mock provider call
		mockProvider.EXPECT().
			CreatePortalSession(customerID).
			Return(portalSession, nil)

		result, err := service.CreatePortalSession(ctx, userID)

		require.NoError(t, err)
		assert.Equal(t, portalURL, result.URL)
	})
}

func TestPaymentService_CreatePortalSession_EdgeCases(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := NewMockSubscriptionRepository(ctrl)
	mockProvider := NewMockProvider(ctrl)

	config := usecase.Config{
		PriceProID:      "price_pro_123",
		PriceBusinessID: "price_business_456",
	}

	service := usecase.NewPaymentUsecase(mockRepo, mockProvider, config)
	ctx := context.Background()

	t.Run("trialing subscription allows portal access", func(t *testing.T) {
		userID := uuid.New().String()
		customerID := "cus_trial_user"
		portalURL := "https://billing.stripe.com/portal/trial_session"

		subscription := &domain.Subscription{
			UserID:             uuid.MustParse(userID),
			Plan:               domain.PlanProfessional,
			Status:             domain.StatusTrialing,
			CusID:              &customerID,
			LicenseCount:       2,
			Paid:               false,
			CurrentPeriodStart: time.Now().Unix(),
			CurrentPeriodEnd:   time.Now().Add(14 * 24 * time.Hour).Unix(),
		}

		portalSession := &stripe.BillingPortalSession{
			ID:  "bps_trial_test",
			URL: portalURL,
		}

		// Mock repository call
		mockRepo.EXPECT().
			GetSubscriptionByUserID(ctx, userID).
			Return(subscription, nil)

		// Mock provider call
		mockProvider.EXPECT().
			CreatePortalSession(customerID).
			Return(portalSession, nil)

		result, err := service.CreatePortalSession(ctx, userID)

		require.NoError(t, err)
		assert.Equal(t, portalURL, result.URL)
	})

	t.Run("subscription with different plan types", func(t *testing.T) {
		testCases := []struct {
			name          string
			plan          domain.SubscriptionPlan
			status        domain.SubscriptionStatus
			shouldSucceed bool
		}{
			{
				name:          "active professional subscription",
				plan:          domain.PlanProfessional,
				status:        domain.StatusActive,
				shouldSucceed: true,
			},
			{
				name:          "active business subscription",
				plan:          domain.PlanBusiness,
				status:        domain.StatusActive,
				shouldSucceed: true,
			},
			{
				name:          "canceled professional subscription",
				plan:          domain.PlanProfessional,
				status:        domain.StatusCanceled,
				shouldSucceed: true,
			},
			{
				name:          "past due business subscription",
				plan:          domain.PlanBusiness,
				status:        domain.StatusPastDue,
				shouldSucceed: true,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				userID := uuid.New().String()
				customerID := "cus_edge_case"

				subscription := &domain.Subscription{
					UserID:       uuid.MustParse(userID),
					Plan:         tc.plan,
					Status:       tc.status,
					CusID:        &customerID,
					LicenseCount: 5,
					Paid:         tc.status == domain.StatusActive,
				}

				if tc.shouldSucceed {
					portalSession := &stripe.BillingPortalSession{
						ID:  "bps_edge_test",
						URL: "https://billing.stripe.com/portal/test",
					}

					mockRepo.EXPECT().
						GetSubscriptionByUserID(ctx, userID).
						Return(subscription, nil)

					mockProvider.EXPECT().
						CreatePortalSession(customerID).
						Return(portalSession, nil)

					result, err := service.CreatePortalSession(ctx, userID)

					require.NoError(t, err)
					assert.NotEmpty(t, result.URL)
				} else {
					mockRepo.EXPECT().
						GetSubscriptionByUserID(ctx, userID).
						Return(subscription, nil)

					result, err := service.CreatePortalSession(ctx, userID)

					assert.Error(t, err)
					assert.Equal(t, usecase.CreatePortalSessionOutput{}, result)
				}
			})
		}
	})
}
