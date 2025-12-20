package middleware

import (
	"context"
	"net/http"

	"my_project/internal/payment/domain"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

var subscriptionDBPool *pgxpool.Pool

func InitSubscriptionMiddleware(pool *pgxpool.Pool) {
	subscriptionDBPool = pool
}

type UserInfo struct {
	UserID         string
	Email          string
	Plan           domain.SubscriptionPlan
	Status         domain.SubscriptionStatus
	CustomerID     *string
	SubscriptionID *string
}

func getSubscription(ctx context.Context, userID string) (*UserInfo, error) {
	query := `
		SELECT s.plan, s.status, s.cus_id, s.sub_id
		FROM subscriptions s
		WHERE s.user_id = $1
		AND s.status IN ('active')
		LIMIT 1
	`

	var plan domain.SubscriptionPlan
	var status domain.SubscriptionStatus
	var customerID, subscriptionID string
	err := subscriptionDBPool.QueryRow(ctx, query, userID).Scan(
		&plan, &status, &customerID, &subscriptionID,
	)

	if err != nil {
		return nil, err
	}

	userInfo := &UserInfo{
		UserID:         userID,
		Plan:           plan,
		Status:         status,
		CustomerID:     &customerID,
		SubscriptionID: &subscriptionID,
	}

	return userInfo, nil
}

func requirePlan(requiredPlans ...domain.SubscriptionPlan) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			userID, ok := c.Get("user_id").(string)
			if !ok || userID == "" {
				return c.JSON(http.StatusUnauthorized, echo.Map{
					"error": "unauthorized",
				})
			}

			ctx := c.Request().Context()
			userInfo, err := getSubscription(ctx, userID)
			if err != nil {
				return c.JSON(http.StatusForbidden, echo.Map{
					"error": "valid subscription required",
				})
			}

			hasRequiredPlan := false
			for _, requiredPlan := range requiredPlans {
				if userInfo.Plan == requiredPlan {
					hasRequiredPlan = true
					break
				}
			}

			if !hasRequiredPlan {
				return c.JSON(http.StatusForbidden, echo.Map{
					"error":        "subscription upgrade required",
					"current_plan": userInfo.Plan,
				})
			}

			return next(c)
		}
	}
}

func IsProfessional() echo.MiddlewareFunc {
	return requirePlan(domain.PlanProfessional)
}

func IsBusiness() echo.MiddlewareFunc {
	return requirePlan(domain.PlanBusiness, domain.PlanProfessional)
}
