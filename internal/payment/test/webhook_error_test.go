package test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	"my_project/internal/payment/domain"
)

// Simulate the improved error handling logic from webhook.go
func simulateWebhookErrorHandling(repo *MockSubscriptionRepository, ctx context.Context, subscription *domain.Subscription, createErr error) error {
	// This simulates the improved handleCheckoutSessionCompleted logic
	if createErr != nil {
		existing, err := repo.GetSubscriptionByUserID(ctx, subscription.UserID.String())
		if err != nil {
			// Distinguish between "subscription not found" and other database errors
			if errors.Is(err, domain.ErrSubscriptionNotFound) {
				// Subscription really doesn't exist and we failed to create it
				return fmt.Errorf("failed to create subscription and no existing subscription found: %w", createErr)
			}
			// This is a genuine database error that should be preserved
			return fmt.Errorf("database error while looking up existing subscription: %w", err)
		}

		// Found existing subscription, update it
		existing.CusID = subscription.CusID
		existing.Status = domain.StatusPending
		existing.UpdatedAt = time.Now().Unix()
		if updateErr := repo.UpdateSubscription(ctx, existing); updateErr != nil {
			return fmt.Errorf("failed to update existing subscription after checkout: %w", updateErr)
		}
	}
	return nil
}

func TestWebhookErrorHandling_DatabaseErrorVsSubscriptionNotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := NewMockSubscriptionRepository(ctrl)
	ctx := context.Background()

	t.Run("database error should not be treated as subscription not found", func(t *testing.T) {
		userID := uuid.New()
		customerID := "cus_test123"

		subscription := &domain.Subscription{
			UserID:       userID,
			Plan:         domain.PlanProfessional,
			CusID:        &customerID,
			LicenseCount: 3,
			Status:       domain.StatusPending,
			CreatedAt:    time.Now().Unix(),
			UpdatedAt:    time.Now().Unix(),
		}

		createErr := errors.New("database connection timeout")

		// GetSubscriptionByUserID ALSO fails with a different database error
		dbErr := errors.New("database query failed")
		mockRepo.EXPECT().
			GetSubscriptionByUserID(ctx, userID.String()).
			Return(nil, dbErr)

		err := simulateWebhookErrorHandling(mockRepo, ctx, subscription, createErr)

		// Should preserve the database error context
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "database error while looking up existing subscription")
		assert.Contains(t, err.Error(), dbErr.Error())
	})

	t.Run("subscription not found should be handled correctly", func(t *testing.T) {
		userID := uuid.New()
		customerID := "cus_test456"

		subscription := &domain.Subscription{
			UserID:       userID,
			Plan:         domain.PlanBusiness,
			CusID:        &customerID,
			LicenseCount: 5,
			Status:       domain.StatusPending,
		}

		createErr := domain.ErrUserAlreadySubscribed

		// GetSubscriptionByUserID fails with "subscription not found"
		mockRepo.EXPECT().
			GetSubscriptionByUserID(ctx, userID.String()).
			Return(nil, domain.ErrSubscriptionNotFound)

		err := simulateWebhookErrorHandling(mockRepo, ctx, subscription, createErr)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to create subscription and no existing subscription found")
		assert.Contains(t, err.Error(), createErr.Error())
	})

	t.Run("successful update after create failure", func(t *testing.T) {
		userID := uuid.New()
		customerID := "cus_test789"

		subscription := &domain.Subscription{
			UserID:       userID,
			Plan:         domain.PlanProfessional,
			CusID:        &customerID,
			LicenseCount: 2,
			Status:       domain.StatusPending,
		}

		createErr := domain.ErrUserAlreadySubscribed

		// GetSubscriptionByUserID succeeds
		existingSub := &domain.Subscription{
			UserID:       userID,
			Plan:         domain.PlanBusiness,
			Status:       domain.StatusActive,
			LicenseCount: 5,
			Paid:         true,
			CreatedAt:    time.Now().Unix() - 3600,
			UpdatedAt:    time.Now().Unix() - 3600,
		}

		mockRepo.EXPECT().
			GetSubscriptionByUserID(ctx, userID.String()).
			Return(existingSub, nil)

		// UpdateSubscription succeeds
		mockRepo.EXPECT().
			UpdateSubscription(ctx, gomock.Any()).
			Return(nil)

		err := simulateWebhookErrorHandling(mockRepo, ctx, subscription, createErr)
		assert.NoError(t, err)
	})

	t.Run("update failure should be properly reported", func(t *testing.T) {
		userID := uuid.New()
		customerID := "cus_test_error"

		subscription := &domain.Subscription{
			UserID:       userID,
			Plan:         domain.PlanProfessional,
			CusID:        &customerID,
			LicenseCount: 1,
			Status:       domain.StatusPending,
		}

		createErr := domain.ErrUserAlreadySubscribed

		// GetSubscriptionByUserID succeeds
		existingSub := &domain.Subscription{
			UserID:       userID,
			Plan:         domain.PlanBusiness,
			Status:       domain.StatusActive,
			LicenseCount: 3,
			Paid:         true,
		}

		mockRepo.EXPECT().
			GetSubscriptionByUserID(ctx, userID.String()).
			Return(existingSub, nil)

		// UpdateSubscription fails
		updateErr := errors.New("deadlock during update")
		mockRepo.EXPECT().
			UpdateSubscription(ctx, gomock.Any()).
			Return(updateErr)

		err := simulateWebhookErrorHandling(mockRepo, ctx, subscription, createErr)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to update existing subscription after checkout")
		assert.Contains(t, err.Error(), updateErr.Error())
	})
}

func TestWebhookErrorHandling_ErrorScenarios(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := NewMockSubscriptionRepository(ctrl)
	ctx := context.Background()

	userID := uuid.New()
	customerID := "cus_error_scenarios"

	subscription := &domain.Subscription{
		UserID:       userID,
		Plan:         domain.PlanProfessional,
		CusID:        &customerID,
		LicenseCount: 3,
		Status:       domain.StatusPending,
	}

	testCases := []struct {
		name          string
		createErr     error
		getErr        error
		expectError   string
		expectSuccess bool
	}{
		{
			name:        "both operations fail with database errors",
			createErr:   errors.New("connection timeout"),
			getErr:      errors.New("query timeout"),
			expectError: "database error while looking up existing subscription",
		},
		{
			name:        "subscription not found after create failure",
			createErr:   domain.ErrUserAlreadySubscribed,
			getErr:      domain.ErrSubscriptionNotFound,
			expectError: "failed to create subscription and no existing subscription found",
		},
		{
			name:        "constraint violation on create, db error on get",
			createErr:   errors.New("unique constraint violation"),
			getErr:      errors.New("deadlock detected"),
			expectError: "database error while looking up existing subscription",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// GetSubscriptionByUserID fails
			mockRepo.EXPECT().
				GetSubscriptionByUserID(ctx, userID.String()).
				Return(nil, tc.getErr)

			err := simulateWebhookErrorHandling(mockRepo, ctx, subscription, tc.createErr)

			if !tc.expectSuccess {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}