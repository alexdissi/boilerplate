package test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"my_project/internal/users/domain"
	"my_project/internal/users/handler"
	"my_project/internal/users/usecase"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestUpdateUserProfile_Usecase(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := NewMockUserRepository(ctrl)
	userUsecase := usecase.NewUserUsecase(mockRepo)

	ctx := context.Background()
	userUUID := uuid.New() // UUID fixe pour le test
	userID := userUUID.String()

	existingUser := &domain.User{
		ID:        userUUID,
		Email:     "old@example.com",
		FirstName: "Old",
		LastName:  "Name",
	}

	t.Run("success - update email only", func(t *testing.T) {
		newEmail := "new@example.com"
		req := usecase.UpdateUserRequest{
			Email: &newEmail,
		}

		updatedUser := *existingUser
		updatedUser.Email = newEmail

		mockRepo.EXPECT().GetUserByID(gomock.Any(), gomock.Eq(userUUID)).Return(existingUser, nil)
		mockRepo.EXPECT().UpdateUser(gomock.Any(), gomock.Any()).Return(&updatedUser, nil)

		result, err := userUsecase.UpdateUserProfile(ctx, userID, req)

		require.NoError(t, err)
		assert.Equal(t, newEmail, result.Email)
		assert.Equal(t, existingUser.FirstName, result.FirstName)
		assert.Equal(t, existingUser.LastName, result.LastName)
	})

	t.Run("success - update first name only", func(t *testing.T) {
		newFirstName := "NewFirst"
		req := usecase.UpdateUserRequest{
			FirstName: &newFirstName,
		}

		updatedUser := *existingUser
		updatedUser.FirstName = newFirstName

		mockRepo.EXPECT().GetUserByID(gomock.Any(), gomock.Eq(userUUID)).Return(existingUser, nil)
		mockRepo.EXPECT().UpdateUser(gomock.Any(), gomock.Any()).Return(&updatedUser, nil)

		result, err := userUsecase.UpdateUserProfile(ctx, userID, req)

		require.NoError(t, err)
		assert.Equal(t, existingUser.Email, result.Email)
		assert.Equal(t, newFirstName, result.FirstName)
		assert.Equal(t, existingUser.LastName, result.LastName)
	})

	t.Run("success - update last name only", func(t *testing.T) {
		newLastName := "NewLast"
		req := usecase.UpdateUserRequest{
			LastName: &newLastName,
		}

		updatedUser := *existingUser
		updatedUser.LastName = newLastName

		mockRepo.EXPECT().GetUserByID(gomock.Any(), gomock.Eq(userUUID)).Return(existingUser, nil)
		mockRepo.EXPECT().UpdateUser(gomock.Any(), gomock.Any()).Return(&updatedUser, nil)

		result, err := userUsecase.UpdateUserProfile(ctx, userID, req)

		require.NoError(t, err)
		assert.Equal(t, existingUser.Email, result.Email)
		assert.Equal(t, existingUser.FirstName, result.FirstName)
		assert.Equal(t, newLastName, result.LastName)
	})

	t.Run("error - invalid user ID", func(t *testing.T) {
		req := usecase.UpdateUserRequest{
			Email: stringPtr("test@example.com"),
		}

		_, err := userUsecase.UpdateUserProfile(ctx, "invalid-uuid", req)

		assert.Error(t, err)
		assert.Equal(t, domain.ErrInvalidUserID, err)
	})
}

func TestUpdateUserProfile_Handler(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUsecase := NewMockUserUsecase(ctrl)
	validator := validator.New()
	userHandler := handler.NewUserHandler(mockUsecase, validator)

	e := echo.New()

	userID := uuid.New().String()
	validEmail := "test@example.com"

	t.Run("success - update email only", func(t *testing.T) {
		reqBody := map[string]interface{}{
			"email": validEmail,
		}

		reqJSON, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPatch, "/users/me", bytes.NewBuffer(reqJSON))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("user_id", userID)

		expectedResponse := usecase.UserProfileResponse{
			ID:        userID,
			Email:     validEmail,
			FirstName: "Old",
			LastName:  "Name",
		}

		mockUsecase.EXPECT().
			UpdateUserProfile(gomock.Any(), userID, gomock.Any()).
			Return(expectedResponse, nil)

		err := userHandler.UpdateUserProfile(c)

		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response usecase.UserProfileResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, expectedResponse.Email, response.Email)
	})

	t.Run("error - unauthorized (no user_id)", func(t *testing.T) {
		reqBody := map[string]interface{}{
			"email": validEmail,
		}

		reqJSON, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPatch, "/users/me", bytes.NewBuffer(reqJSON))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := userHandler.UpdateUserProfile(c)

		require.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)

		var response map[string]string
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, "Unauthorized", response["error"])
	})

	t.Run("error - validation failed (invalid email)", func(t *testing.T) {
		reqBody := map[string]interface{}{
			"email": "invalid-email",
		}

		reqJSON, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPatch, "/users/me", bytes.NewBuffer(reqJSON))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("user_id", userID)

		err := userHandler.UpdateUserProfile(c)

		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Code)

		var response map[string]string
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Contains(t, response["error"], "Validation failed")
	})

	t.Run("error - validation failed (first name too short)", func(t *testing.T) {
		reqBody := map[string]interface{}{
			"first_name": "a", // Less than 2 characters
		}

		reqJSON, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPatch, "/users/me", bytes.NewBuffer(reqJSON))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("user_id", userID)

		err := userHandler.UpdateUserProfile(c)

		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("error - no fields provided", func(t *testing.T) {
		reqBody := map[string]interface{}{}

		reqJSON, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPatch, "/users/me", bytes.NewBuffer(reqJSON))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("user_id", userID)

		err := userHandler.UpdateUserProfile(c)

		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Code)

		var response map[string]string
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, "At least one field must be provided", response["error"])
	})

	t.Run("error - usecase returns error", func(t *testing.T) {
		reqBody := map[string]interface{}{
			"email": validEmail,
		}

		reqJSON, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPatch, "/users/me", bytes.NewBuffer(reqJSON))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("user_id", userID)

		mockUsecase.EXPECT().
			UpdateUserProfile(gomock.Any(), userID, gomock.Any()).
			Return(usecase.UserProfileResponse{}, errors.New("usecase error"))

		err := userHandler.UpdateUserProfile(c)

		require.NoError(t, err)
		assert.Equal(t, http.StatusInternalServerError, rec.Code)

		var response map[string]string
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, "usecase error", response["error"])
	})
}

func stringPtr(s string) *string {
	return &s
}
