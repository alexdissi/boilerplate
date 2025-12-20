package test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"my_project/internal/payment/domain"
)

func TestMockSubscriptionRepository_CreateSubscription(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := NewMockSubscriptionRepository(ctrl)
	ctx := context.Background()

	t.Run("successful creation", func(t *testing.T) {
		subscription := &domain.Subscription{
			UserID:       uuid.New(),
			Plan:         domain.PlanProfessional,
			LicenseCount: 5,
			Status:       domain.StatusActive,
			Paid:         true,
			CreatedAt:    time.Now().Unix(),
			UpdatedAt:    time.Now().Unix(),
		}

		mockRepo.EXPECT().
			CreateSubscription(ctx, subscription).
			Return(nil)

		err := mockRepo.CreateSubscription(ctx, subscription)
		assert.NoError(t, err)
	})

	t.Run("creation error", func(t *testing.T) {
		subscription := &domain.Subscription{
			UserID:       uuid.New(),
			Plan:         domain.PlanBusiness,
			LicenseCount: 3,
		}

		expectedErr := errors.New("database error")
		mockRepo.EXPECT().
			CreateSubscription(ctx, subscription).
			Return(expectedErr)

		err := mockRepo.CreateSubscription(ctx, subscription)
		assert.Error(t, err)
		assert.Equal(t, expectedErr, err)
	})
}

func TestMockSubscriptionRepository_GetSubscriptionByUserID(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := NewMockSubscriptionRepository(ctrl)
	ctx := context.Background()

	t.Run("subscription found", func(t *testing.T) {
		userID := uuid.New()
		expectedSub := &domain.Subscription{
			UserID:             userID,
			Plan:               domain.PlanProfessional,
			LicenseCount:       10,
			Status:             domain.StatusActive,
			Paid:               true,
			CurrentPeriodStart: time.Now().Unix(),
			CurrentPeriodEnd:   time.Now().Add(30 * 24 * time.Hour).Unix(),
		}

		mockRepo.EXPECT().
			GetSubscriptionByUserID(ctx, userID.String()).
			Return(expectedSub, nil)

		sub, err := mockRepo.GetSubscriptionByUserID(ctx, userID.String())
		require.NoError(t, err)
		assert.Equal(t, expectedSub, sub)
		assert.Equal(t, userID, sub.UserID)
		assert.Equal(t, domain.PlanProfessional, sub.Plan)
		assert.True(t, sub.IsActive())
	})

	t.Run("subscription not found", func(t *testing.T) {
		userID := uuid.New()
		expectedErr := errors.New("subscription not found")

		mockRepo.EXPECT().
			GetSubscriptionByUserID(ctx, userID.String()).
			Return(nil, expectedErr)

		sub, err := mockRepo.GetSubscriptionByUserID(ctx, userID.String())
		assert.Error(t, err)
		assert.Nil(t, sub)
		assert.Equal(t, expectedErr, err)
	})
}

func TestMockSubscriptionRepository_GetSubscriptionBySubID(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := NewMockSubscriptionRepository(ctrl)
	ctx := context.Background()

	t.Run("subscription found by sub ID", func(t *testing.T) {
		subID := "sub_1234567890"
		expectedSub := &domain.Subscription{
			UserID:       uuid.New(),
			Plan:         domain.PlanBusiness,
			SubID:        &subID,
			LicenseCount: 5,
			Status:       domain.StatusTrialing,
			Paid:         false,
		}

		mockRepo.EXPECT().
			GetSubscriptionBySubID(ctx, subID).
			Return(expectedSub, nil)

		sub, err := mockRepo.GetSubscriptionBySubID(ctx, subID)
		require.NoError(t, err)
		assert.Equal(t, expectedSub, sub)
		assert.Equal(t, subID, *sub.SubID)
		assert.True(t, sub.IsActive())
		assert.False(t, sub.Paid)
	})

	t.Run("subscription not found by sub ID", func(t *testing.T) {
		subID := "nonexistent_sub"
		expectedErr := errors.New("subscription not found")

		mockRepo.EXPECT().
			GetSubscriptionBySubID(ctx, subID).
			Return(nil, expectedErr)

		sub, err := mockRepo.GetSubscriptionBySubID(ctx, subID)
		assert.Error(t, err)
		assert.Nil(t, sub)
		assert.Equal(t, expectedErr, err)
	})
}

func TestMockSubscriptionRepository_GetSubscriptionByCustomerID(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := NewMockSubscriptionRepository(ctrl)
	ctx := context.Background()

	t.Run("subscription found by customer ID", func(t *testing.T) {
		cusID := "cus_1234567890"
		expectedSub := &domain.Subscription{
			UserID:       uuid.New(),
			Plan:         domain.PlanProfessional,
			CusID:        &cusID,
			LicenseCount: 15,
			Status:       domain.StatusActive,
			Paid:         true,
		}

		mockRepo.EXPECT().
			GetSubscriptionByCustomerID(ctx, cusID).
			Return(expectedSub, nil)

		sub, err := mockRepo.GetSubscriptionByCustomerID(ctx, cusID)
		require.NoError(t, err)
		assert.Equal(t, expectedSub, sub)
		assert.Equal(t, cusID, *sub.CusID)
		assert.True(t, sub.IsActive())
		assert.True(t, sub.Paid)
	})

	t.Run("subscription not found by customer ID", func(t *testing.T) {
		cusID := "cus_nonexistent"
		expectedErr := errors.New("customer not found")

		mockRepo.EXPECT().
			GetSubscriptionByCustomerID(ctx, cusID).
			Return(nil, expectedErr)

		sub, err := mockRepo.GetSubscriptionByCustomerID(ctx, cusID)
		assert.Error(t, err)
		assert.Nil(t, sub)
		assert.Equal(t, expectedErr, err)
	})
}

func TestMockSubscriptionRepository_UpdateSubscription(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := NewMockSubscriptionRepository(ctrl)
	ctx := context.Background()

	t.Run("successful update", func(t *testing.T) {
		subID := "sub_update_test"
		subscription := &domain.Subscription{
			UserID:             uuid.New(),
			Plan:               domain.PlanProfessional,
			SubID:              &subID,
			LicenseCount:       20,
			Status:             domain.StatusActive,
			Paid:               true,
			CurrentPeriodEnd:   time.Now().Add(30 * 24 * time.Hour).Unix(),
			UpdatedAt:          time.Now().Unix(),
		}

		mockRepo.EXPECT().
			UpdateSubscription(ctx, subscription).
			Return(nil)

		err := mockRepo.UpdateSubscription(ctx, subscription)
		assert.NoError(t, err)
	})

	t.Run("update error", func(t *testing.T) {
		subscription := &domain.Subscription{
			UserID:       uuid.New(),
			Plan:         domain.PlanBusiness,
			LicenseCount: 8,
			Status:       domain.StatusPastDue,
		}

		expectedErr := errors.New("update failed")
		mockRepo.EXPECT().
			UpdateSubscription(ctx, subscription).
			Return(expectedErr)

		err := mockRepo.UpdateSubscription(ctx, subscription)
		assert.Error(t, err)
		assert.Equal(t, expectedErr, err)
	})
}

func TestMockSubscriptionRepository_IntegrationScenarios(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := NewMockSubscriptionRepository(ctrl)
	ctx := context.Background()

	t.Run("subscription lifecycle", func(t *testing.T) {
		userID := uuid.New()
		subID := "sub_lifecycle_test"
		cusID := "cus_lifecycle_test"

		// Create subscription
		newSub := &domain.Subscription{
			UserID:       userID,
			Plan:         domain.PlanFree,
			LicenseCount: 1,
			Status:       domain.StatusPending,
			Paid:         false,
			CreatedAt:    time.Now().Unix(),
			UpdatedAt:    time.Now().Unix(),
		}

		mockRepo.EXPECT().
			CreateSubscription(ctx, newSub).
			Return(nil)

		err := mockRepo.CreateSubscription(ctx, newSub)
		require.NoError(t, err)

		// Update to active subscription
		activeSub := *newSub
		activeSub.Plan = domain.PlanProfessional
		activeSub.SubID = &subID
		activeSub.CusID = &cusID
		activeSub.LicenseCount = 10
		activeSub.Status = domain.StatusActive
		activeSub.Paid = true
		activeSub.UpdatedAt = time.Now().Unix()

		mockRepo.EXPECT().
			UpdateSubscription(ctx, &activeSub).
			Return(nil)

		err = mockRepo.UpdateSubscription(ctx, &activeSub)
		require.NoError(t, err)

		// Retrieve by user ID
		mockRepo.EXPECT().
			GetSubscriptionByUserID(ctx, userID.String()).
			Return(&activeSub, nil)

		retrievedSub, err := mockRepo.GetSubscriptionByUserID(ctx, userID.String())
		require.NoError(t, err)
		assert.Equal(t, domain.StatusActive, retrievedSub.Status)
		assert.True(t, retrievedSub.IsActive())

		// Retrieve by subscription ID
		mockRepo.EXPECT().
			GetSubscriptionBySubID(ctx, subID).
			Return(&activeSub, nil)

		retrievedBySubID, err := mockRepo.GetSubscriptionBySubID(ctx, subID)
		require.NoError(t, err)
		assert.Equal(t, &activeSub, retrievedBySubID)

		// Retrieve by customer ID
		mockRepo.EXPECT().
			GetSubscriptionByCustomerID(ctx, cusID).
			Return(&activeSub, nil)

		retrievedByCusID, err := mockRepo.GetSubscriptionByCustomerID(ctx, cusID)
		require.NoError(t, err)
		assert.Equal(t, &activeSub, retrievedByCusID)
	})

	t.Run("subscription cancellation scenario", func(t *testing.T) {
		userID := uuid.New()
		canceledSub := &domain.Subscription{
			UserID:            userID,
			Plan:              domain.PlanBusiness,
			LicenseCount:      5,
			Status:            domain.StatusCanceled,
			Paid:              true,
			CancelAtPeriodEnd: true,
			UpdatedAt:         time.Now().Unix(),
		}

		// Get the subscription
		mockRepo.EXPECT().
			GetSubscriptionByUserID(ctx, userID.String()).
			Return(canceledSub, nil)

		sub, err := mockRepo.GetSubscriptionByUserID(ctx, userID.String())
		require.NoError(t, err)

		// Verify it's canceled but was paid
		assert.True(t, sub.IsCanceled())
		assert.True(t, sub.ShouldCancelAtPeriodEnd())
		assert.True(t, sub.Paid)
		assert.False(t, sub.IsActive())
	})
}

func TestSubscriptionBusinessLogic(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := NewMockSubscriptionRepository(ctrl)
	ctx := context.Background()

	t.Run("validate subscription status transitions", func(t *testing.T) {
		userID := uuid.New()
		userIDStr := userID.String()

		// Test pending to active transition
		pendingSub := &domain.Subscription{
			UserID:       userID,
			Plan:         domain.PlanProfessional,
			LicenseCount: 3,
			Status:       domain.StatusPending,
			Paid:         false,
		}

		// Return pending subscription
		mockRepo.EXPECT().
			GetSubscriptionByUserID(ctx, userIDStr).
			Return(pendingSub, nil)

		// Verify initial state
		sub, err := mockRepo.GetSubscriptionByUserID(ctx, userIDStr)
		require.NoError(t, err)
		assert.False(t, sub.IsActive())
		assert.False(t, sub.IsCanceled())
		assert.False(t, sub.Paid)

		// Simulate payment and activation
		activeSub := *sub
		activeSub.Status = domain.StatusActive
		activeSub.Paid = true
		activeSub.CurrentPeriodStart = time.Now().Unix()
		activeSub.CurrentPeriodEnd = time.Now().Add(30 * 24 * time.Hour).Unix()

		mockRepo.EXPECT().
			UpdateSubscription(ctx, &activeSub).
			Return(nil)

		err = mockRepo.UpdateSubscription(ctx, &activeSub)
		require.NoError(t, err)

		// Return updated subscription for verification
		mockRepo.EXPECT().
			GetSubscriptionByUserID(ctx, userIDStr).
			Return(&activeSub, nil)

		// Verify activation
		sub, err = mockRepo.GetSubscriptionByUserID(ctx, userIDStr)
		require.NoError(t, err)
		assert.True(t, sub.IsActive())
		assert.True(t, sub.Paid)
		assert.Equal(t, domain.StatusActive, sub.Status)
	})

	t.Run("validate subscription helpers", func(t *testing.T) {
		// Test active subscription
		activeSub := &domain.Subscription{
			Status: domain.StatusActive,
		}
		assert.True(t, activeSub.IsActive())
		assert.False(t, activeSub.IsCanceled())

		// Test trial subscription
		trialSub := &domain.Subscription{
			Status: domain.StatusTrialing,
		}
		assert.True(t, trialSub.IsActive())
		assert.False(t, trialSub.IsCanceled())

		// Test canceled subscription
		canceledSub := &domain.Subscription{
			Status:            domain.StatusCanceled,
			CancelAtPeriodEnd: true,
		}
		assert.False(t, canceledSub.IsActive())
		assert.True(t, canceledSub.IsCanceled())
		assert.True(t, canceledSub.ShouldCancelAtPeriodEnd())

		// Test past due subscription
		pastDueSub := &domain.Subscription{
			Status: domain.StatusPastDue,
		}
		assert.False(t, pastDueSub.IsActive())
		assert.False(t, pastDueSub.IsCanceled())
	})
}