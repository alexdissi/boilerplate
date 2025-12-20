package domain

import (
	"github.com/google/uuid"
)

type SubscriptionPlan string

const (
	PlanFree         SubscriptionPlan = "FREE"
	PlanBusiness     SubscriptionPlan = "BUSINESS"
	PlanProfessional SubscriptionPlan = "PROFESSIONAL"
)

type SubscriptionStatus string

const (
	StatusActive   SubscriptionStatus = "active"
	StatusCanceled SubscriptionStatus = "canceled"
	StatusPending  SubscriptionStatus = "pending"
	StatusTrialing SubscriptionStatus = "trialing"
	StatusPastDue  SubscriptionStatus = "past_due"
)

type Subscription struct {
	UserID             uuid.UUID          `json:"user_id" db:"user_id"`
	Plan               SubscriptionPlan   `json:"plan" db:"plan"`
	SubID              *string            `json:"sub_id" db:"sub_id"`
	CusID              *string            `json:"cus_id" db:"cus_id"`
	LicenseCount       int                `json:"license_count" db:"license_count"`
	Status             SubscriptionStatus `json:"status" db:"status"`
	Paid               bool               `json:"paid" db:"paid"`
	CurrentPeriodStart int64              `json:"current_period_start" db:"current_period_start"`
	CurrentPeriodEnd   int64              `json:"current_period_end" db:"current_period_end"`
	CancelAtPeriodEnd  bool               `json:"cancel_at_period_end" db:"cancel_at_period_end"`
	CreatedAt          int64              `json:"created_at" db:"created_at"`
	UpdatedAt          int64              `json:"updated_at" db:"updated_at"`
}

func IsValidPlan(plan SubscriptionPlan) bool {
	switch plan {
	case PlanFree, PlanBusiness, PlanProfessional:
		return true
	default:
		return false
	}
}

func (s *Subscription) IsActive() bool {
	return s.Status == StatusActive || s.Status == StatusTrialing
}

func (s *Subscription) IsCanceled() bool {
	return s.Status == StatusCanceled
}

func (s *Subscription) ShouldCancelAtPeriodEnd() bool {
	return s.CancelAtPeriodEnd
}
