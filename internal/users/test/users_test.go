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
	passwordValidator "my_project/pkg/validator"
	"my_project/pkg/logger"
	"my_project/pkg/password"

	"github.com/google/uuid"
	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

type CustomValidator struct {
	validator *validator.Validate
}

func (cv *CustomValidator) Validate(i interface{}) error {
	if err := cv.validator.Struct(i); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	return nil
}

func TestUpdateUserProfile_Usecase(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := NewMockUserRepository(ctrl)
	userUsecase := usecase.NewUserUsecase(mockRepo, nil)

	ctx := context.Background()
	userUUID := uuid.New()
	userID := userUUID.String()

	existingUser := &domain.User{
		ID:        userUUID,
		Email:     "old@example.com",
		FirstName: "Old",
		LastName:  "Name",
	}

	t.Run("success scenarios", func(t *testing.T) {
		tests := []struct {
			name string
			req  usecase.UpdateUserRequest
			want usecase.UserProfileResponse
		}{
			{
				name: "update email only",
				req:  usecase.UpdateUserRequest{Email: stringPtr("new@example.com")},
				want: usecase.UserProfileResponse{Email: "new@example.com", FirstName: "Old", LastName: "Name"},
			},
			{
				name: "update first name only",
				req:  usecase.UpdateUserRequest{FirstName: stringPtr("NewFirst")},
				want: usecase.UserProfileResponse{Email: "old@example.com", FirstName: "NewFirst", LastName: "Name"},
			},
			{
				name: "update last name only",
				req:  usecase.UpdateUserRequest{LastName: stringPtr("NewLast")},
				want: usecase.UserProfileResponse{Email: "old@example.com", FirstName: "Old", LastName: "NewLast"},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				updatedUser := *existingUser
				if tt.req.Email != nil {
					updatedUser.Email = *tt.req.Email
				}
				if tt.req.FirstName != nil {
					updatedUser.FirstName = *tt.req.FirstName
				}
				if tt.req.LastName != nil {
					updatedUser.LastName = *tt.req.LastName
				}

				mockRepo.EXPECT().GetPublicProfileByID(gomock.Any(), userUUID).Return(existingUser, nil)
				mockRepo.EXPECT().UpdateUser(gomock.Any(), gomock.Any()).Return(&updatedUser, nil)

				result, err := userUsecase.UpdateUserProfile(ctx, userID, tt.req)

				require.NoError(t, err)
				assert.Equal(t, updatedUser.Email, result.Email)
				assert.Equal(t, updatedUser.FirstName, result.FirstName)
				assert.Equal(t, updatedUser.LastName, result.LastName)
			})
		}
	})

	t.Run("error - invalid user ID", func(t *testing.T) {
		req := usecase.UpdateUserRequest{Email: stringPtr("test@example.com")}
		_, err := userUsecase.UpdateUserProfile(ctx, "invalid-uuid", req)
		assert.Error(t, err)
		assert.Equal(t, domain.ErrInvalidUserID, err)
	})
}

func TestUpdateUserProfile_Handler(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUsecase := NewMockUserUsecase(ctrl)
	userHandler := handler.NewUserHandler(mockUsecase)

	e := echo.New()
	v := validator.New()
	passwordValidator.RegisterPasswordValidation(v)
	e.Validator = &CustomValidator{validator: v}
	userID := uuid.New().String()

	t.Run("success", func(t *testing.T) {
		reqBody := map[string]string{"email": "test@example.com"}
		reqJSON, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPatch, "/users/me", bytes.NewBuffer(reqJSON))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("user_id", userID)

		expectedResponse := usecase.UserProfileResponse{ID: userID, Email: "test@example.com"}
		mockUsecase.EXPECT().UpdateUserProfile(gomock.Any(), userID, gomock.Any()).Return(expectedResponse, nil)

		err := userHandler.UpdateUserProfile(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response usecase.UserProfileResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, expectedResponse.Email, response.Email)
	})

	t.Run("error scenarios", func(t *testing.T) {
		tests := []struct {
			name          string
			reqBody       any
			expectedCode  int
			expectedError string
			setupMock     func()
		}{
			{
				name:          "unauthorized",
				reqBody:       map[string]string{"email": "test@example.com"},
				expectedCode:  http.StatusUnauthorized,
				expectedError: "Unauthorized",
			},
			{
				name:          "invalid email",
				reqBody:       map[string]string{"email": "invalid-email"},
				expectedCode:  http.StatusBadRequest,
				expectedError: "Field validation for 'Email' failed",
			},
			{
				name:          "first name too short",
				reqBody:       map[string]string{"first_name": "a"},
				expectedCode:  http.StatusBadRequest,
				expectedError: "Field validation for 'FirstName' failed",
			},
			{
				name:          "no fields provided",
				reqBody:       map[string]any{},
				expectedCode:  http.StatusBadRequest,
				expectedError: "At least one field must be provided",
			},
			{
				name:          "usecase error",
				reqBody:       map[string]string{"email": "test@example.com"},
				expectedCode:  http.StatusInternalServerError,
				expectedError: "usecase error",
				setupMock: func() {
					mockUsecase.EXPECT().UpdateUserProfile(gomock.Any(), userID, gomock.Any()).
						Return(usecase.UserProfileResponse{}, errors.New("usecase error"))
				},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if tt.setupMock != nil {
					tt.setupMock()
				}

				reqJSON, _ := json.Marshal(tt.reqBody)
				req := httptest.NewRequest(http.MethodPatch, "/users/me", bytes.NewBuffer(reqJSON))
				req.Header.Set("Content-Type", "application/json")
				rec := httptest.NewRecorder()
				c := e.NewContext(req, rec)
				if tt.name != "unauthorized" {
					c.Set("user_id", userID)
				}

				err := userHandler.UpdateUserProfile(c)
				// Handle HTTPError from Echo's validator
				if httpErr, ok := err.(*echo.HTTPError); ok {
					assert.Equal(t, tt.expectedCode, httpErr.Code)
					// Extract error message from HTTPError
					if errMsg, ok := httpErr.Message.(string); ok {
						assert.Contains(t, errMsg, tt.expectedError)
					}
					return
				}
				require.NoError(t, err)
				assert.Equal(t, tt.expectedCode, rec.Code)

				var response map[string]string
				err = json.Unmarshal(rec.Body.Bytes(), &response)
				require.NoError(t, err)
				assert.Contains(t, response["error"], tt.expectedError)
			})
		}
	})
}

func TestChangePassword_Usecase(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	logger.Init()

	mockRepo := NewMockUserRepository(ctrl)
	userUsecase := usecase.NewUserUsecase(mockRepo, nil)

	ctx := context.Background()
	userUUID := uuid.New()
	userID := userUUID.String()
	currentPassword := "oldPassword123!"
	newPassword := "newPassword456!"

	hashedCurrentPassword, err := password.HashPassword(currentPassword)
	require.NoError(t, err)

	existingUser := &domain.User{
		ID:           userUUID,
		Email:        "test@example.com",
		FirstName:    "Test",
		LastName:     "User",
		PasswordHash: hashedCurrentPassword,
	}

	t.Run("success", func(t *testing.T) {
		req := usecase.ChangePasswordRequest{
			CurrentPassword: currentPassword,
			NewPassword:     newPassword,
		}

		mockRepo.EXPECT().GetPublicProfileByID(gomock.Any(), userUUID).Return(existingUser, nil)
		mockRepo.EXPECT().UpdatePassword(gomock.Any(), userUUID, gomock.Any()).Return(nil)

		err := userUsecase.ChangePassword(ctx, userID, req)
		require.NoError(t, err)
	})

	t.Run("error scenarios", func(t *testing.T) {
		tests := []struct {
			name          string
			userIDForTest string
			req           usecase.ChangePasswordRequest
			setupMock     func()
			expectedError error
		}{
			{
				name:          "invalid user ID",
				userIDForTest: "invalid-uuid",
				req:           usecase.ChangePasswordRequest{CurrentPassword: currentPassword, NewPassword: newPassword},
				expectedError: domain.ErrInvalidUserID,
			},
			{
				name:          "user not found",
				userIDForTest: userID,
				req:           usecase.ChangePasswordRequest{CurrentPassword: currentPassword, NewPassword: newPassword},
				setupMock: func() {
					mockRepo.EXPECT().GetPublicProfileByID(gomock.Any(), userUUID).Return(nil, domain.ErrUserNotFound)
				},
				expectedError: domain.ErrUserNotFound,
			},
			{
				name:          "current password incorrect",
				userIDForTest: userID,
				req:           usecase.ChangePasswordRequest{CurrentPassword: "wrongPassword", NewPassword: newPassword},
				setupMock: func() {
					mockRepo.EXPECT().GetPublicProfileByID(gomock.Any(), userUUID).Return(existingUser, nil)
				},
				expectedError: domain.ErrInvalidCurrentPassword,
			},
			{
				name:          "failed to update password",
				userIDForTest: userID,
				req:           usecase.ChangePasswordRequest{CurrentPassword: currentPassword, NewPassword: newPassword},
				setupMock: func() {
					mockRepo.EXPECT().GetPublicProfileByID(gomock.Any(), userUUID).Return(existingUser, nil)
					mockRepo.EXPECT().UpdatePassword(gomock.Any(), userUUID, gomock.Any()).Return(errors.New("database error"))
				},
				expectedError: errors.New("failed to update password: database error"),
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if tt.setupMock != nil {
					tt.setupMock()
				}

				err := userUsecase.ChangePassword(ctx, tt.userIDForTest, tt.req)
				assert.Error(t, err)
				if tt.name == "invalid user ID" {
					assert.Equal(t, tt.expectedError, err)
				} else if tt.name == "failed to update password" {
					assert.Contains(t, err.Error(), "failed to update user")
				} else {
					assert.Contains(t, err.Error(), tt.expectedError.Error())
				}
			})
		}
	})
}

func TestChangePassword_Handler(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	logger.Init()

	mockUsecase := NewMockUserUsecase(ctrl)
	userHandler := handler.NewUserHandler(mockUsecase)

	e := echo.New()
	v := validator.New()
	passwordValidator.RegisterPasswordValidation(v)
	e.Validator = &CustomValidator{validator: v}
	userID := uuid.New().String()

	t.Run("success", func(t *testing.T) {
		reqBody := map[string]string{
			"current_password": "oldPassword123!",
			"new_password":     "newPassword456!",
		}
		reqJSON, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/users/change-password", bytes.NewBuffer(reqJSON))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("user_id", userID)

		mockUsecase.EXPECT().ChangePassword(gomock.Any(), userID, gomock.Any()).Return(nil)

		err := userHandler.ChangePassword(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response map[string]string
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, "Password changed successfully", response["message"])
	})

	t.Run("error scenarios", func(t *testing.T) {
		tests := []struct {
			name          string
			reqBody       any
			expectedCode  int
			expectedError string
			setupMock     func()
		}{
			{
				name:          "unauthorized",
				reqBody:       map[string]string{"current_password": "old!", "new_password": "new!"},
				expectedCode:  http.StatusUnauthorized,
				expectedError: "Unauthorized",
			},
			{
				name:          "missing current password",
				reqBody:       map[string]string{"new_password": "newPassword456!"},
				expectedCode:  http.StatusBadRequest,
				expectedError: "Field validation for 'CurrentPassword' failed",
			},
			{
				name:          "password too short",
				reqBody:       map[string]string{"current_password": "old!", "new_password": "short"},
				expectedCode:  http.StatusBadRequest,
				expectedError: "Field validation for 'NewPassword' failed",
			},
			{
				name:          "weak password",
				reqBody:       map[string]string{"current_password": "old!", "new_password": "weakpassword"},
				expectedCode:  http.StatusBadRequest,
				expectedError: "Field validation for 'NewPassword' failed",
			},
			{
				name:          "same password",
				reqBody:       map[string]string{"current_password": "Password123!", "new_password": "Password123!"},
				expectedCode:  http.StatusBadRequest,
				expectedError: "New password must be different from current password",
			},
			{
				name:          "invalid JSON",
				reqBody:       []byte("invalid json"),
				expectedCode:  http.StatusBadRequest,
				expectedError: "Invalid request format",
			},
			{
				name:          "current password incorrect",
				reqBody:       map[string]string{"current_password": "Password123!", "new_password": "newPassword456!"},
				expectedCode:  http.StatusUnauthorized,
				expectedError: "Current password is incorrect",
				setupMock: func() {
					mockUsecase.EXPECT().ChangePassword(gomock.Any(), userID, gomock.Any()).
						Return(domain.ErrInvalidCurrentPassword)
				},
			},
			{
				name:          "usecase error",
				reqBody:       map[string]string{"current_password": "Password123!", "new_password": "newPassword456!"},
				expectedCode:  http.StatusInternalServerError,
				expectedError: "usecase error",
				setupMock: func() {
					mockUsecase.EXPECT().ChangePassword(gomock.Any(), userID, gomock.Any()).
						Return(errors.New("usecase error"))
				},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if tt.setupMock != nil {
					tt.setupMock()
				}

				var req *http.Request
				switch v := tt.reqBody.(type) {
				case map[string]string:
					reqJSON, _ := json.Marshal(v)
					req = httptest.NewRequest(http.MethodPost, "/users/change-password", bytes.NewBuffer(reqJSON))
					req.Header.Set("Content-Type", "application/json")
				case []byte:
					req = httptest.NewRequest(http.MethodPost, "/users/change-password", bytes.NewBuffer(v))
					req.Header.Set("Content-Type", "application/json")
				}

				rec := httptest.NewRecorder()
				c := e.NewContext(req, rec)
				if tt.name != "unauthorized" {
					c.Set("user_id", userID)
				}

				err := userHandler.ChangePassword(c)
				// Handle HTTPError from Echo's validator
				if httpErr, ok := err.(*echo.HTTPError); ok {
					assert.Equal(t, tt.expectedCode, httpErr.Code)
					// Extract error message from HTTPError
					if errMsg, ok := httpErr.Message.(string); ok {
						assert.Contains(t, errMsg, tt.expectedError)
					}
					return
				}
				require.NoError(t, err)
				assert.Equal(t, tt.expectedCode, rec.Code)

				var response map[string]string
				err = json.Unmarshal(rec.Body.Bytes(), &response)
				require.NoError(t, err)
				if tt.name == "same password" || tt.name == "unauthorized" || tt.name == "invalid JSON" {
					assert.Equal(t, tt.expectedError, response["error"])
				} else {
					assert.Contains(t, response["error"], tt.expectedError)
				}
			})
		}
	})
}

func TestDeleteUser_Usecase(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := NewMockUserRepository(ctrl)
	userUsecase := usecase.NewUserUsecase(mockRepo, nil)

	ctx := context.Background()
	userUUID := uuid.New()
	userID := userUUID.String()

	t.Run("success", func(t *testing.T) {
		mockRepo.EXPECT().DeleteUser(gomock.Any(), userUUID).Return(nil)

		err := userUsecase.DeleteUser(ctx, userID)
		require.NoError(t, err)
	})

	t.Run("error - invalid user ID", func(t *testing.T) {
		err := userUsecase.DeleteUser(ctx, "invalid-uuid")
		assert.Error(t, err)
		assert.Equal(t, domain.ErrInvalidUserID, err)
	})
}

func TestDeleteUser_Handler(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUsecase := NewMockUserUsecase(ctrl)
	userHandler := handler.NewUserHandler(mockUsecase)

	e := echo.New()
	v := validator.New()
	passwordValidator.RegisterPasswordValidation(v)
	e.Validator = &CustomValidator{validator: v}
	userID := uuid.New().String()

	t.Run("success", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/users/me", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("user_id", userID)

		mockUsecase.EXPECT().DeleteUser(gomock.Any(), userID).Return(nil)

		err := userHandler.DeleteUser(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response map[string]string
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, "User deleted successfully", response["message"])
	})

	t.Run("error - unauthorized", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/users/me", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := userHandler.DeleteUser(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)

		var response map[string]string
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, "Unauthorized", response["error"])
	})
}

func stringPtr(s string) *string {
	return &s
}
