package usecase

type GoogleAuthInput struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
}

type GoogleAuthOutput struct {
	User    UserInfo     `json:"user"`
	Session *SessionInfo `json:"-"` // Never expose session in JSON (token sent via HttpOnly cookie)
	Message string       `json:"message"`
}

type GoogleUserInfo struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"verified_email"`
	Name          string `json:"name"`
	FirstName     string `json:"given_name"`
	LastName      string `json:"family_name"`
	Picture       string `json:"picture"`
}

type GoogleTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
}
