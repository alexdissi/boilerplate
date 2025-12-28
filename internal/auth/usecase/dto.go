package usecase

type RegisterUserInput struct {
	FirstName string `json:"firstName" form:"firstName" validate:"required"`
	LastName  string `json:"lastName" form:"lastName" validate:"required"`
	Email     string `json:"email" form:"email" validate:"required,email"`
	Password  string `json:"password" form:"password" validate:"required,strongpassword"`
}

type RegisterUserOutput struct {
	ID      string `json:"id"`
	Email   string `json:"email"`
	Message string `json:"message"`
}

type LoginUserInput struct {
	Email    string `json:"email" form:"email" validate:"required,email"`
	Password string `json:"password" form:"password" validate:"required"`
}

type LoginUserOutput struct {
	User    UserInfo    `json:"user"`
	Session SessionInfo `json:"session"`
	Message string      `json:"message"`
}

type UserInfo struct {
	ID             string `json:"id"`
	Email          string `json:"email"`
	FirstName      string `json:"firstName"`
	LastName       string `json:"lastName"`
	ProfilePicture string `json:"profilePicture"`
}

type SessionInfo struct {
	Token     string `json:"token,omitempty"`
	ExpiresAt string `json:"expiresAt,omitempty"`
}

type LogoutOutput struct {
	Message string `json:"message"`
}

type ForgotPasswordInput struct {
	Email string `json:"email" form:"email" validate:"required,email"`
}

type ForgotPasswordOutput struct {
	Message string `json:"message"`
}

type ResetPasswordInput struct {
	Token    string `json:"token" form:"token" validate:"required"`
	Password string `json:"password" form:"password" validate:"required,strongpassword"`
}

type ResetPasswordOutput struct {
	Message string `json:"message"`
}
