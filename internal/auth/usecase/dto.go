package usecase

type RegisterUserInput struct {
	FirstName string `json:"first_name" form:"first_name"`
	LastName  string `json:"last_name" form:"last_name"`
	Email     string `json:"email" form:"email"`
	Password  string `json:"password" form:"password"`
}

type RegisterUserOutput struct {
	ID      string `json:"id"`
	Email   string `json:"email"`
	Message string `json:"message"`
}

type LoginUserInput struct {
	Email    string `json:"email" form:"email"`
	Password string `json:"password" form:"password"`
}

type LoginUserOutput struct {
	User    UserInfo    `json:"user"`
	Session SessionInfo `json:"session"`
	Message string      `json:"message"`
}

type UserInfo struct {
	ID             string `json:"id"`
	Email          string `json:"email"`
	FirstName      string `json:"first_name"`
	LastName       string `json:"last_name"`
	ProfilePicture string `json:"profile_picture"`
}

type SessionInfo struct {
	Token     string `json:"token,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
}
