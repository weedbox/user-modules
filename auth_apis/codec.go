package auth_apis

import "time"

// ========== Request Structures ==========

// --- Login ---

type LoginRequestBody struct {
	Identifier string `json:"identifier" binding:"required"` // username or email
	Password   string `json:"password" binding:"required"`
}

type LoginRequest struct {
	Body LoginRequestBody
}

// --- Refresh ---

type RefreshRequestBody struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

type RefreshRequest struct {
	Body RefreshRequestBody
}

// --- Logout ---

type LogoutRequestBody struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

type LogoutRequest struct {
	Body LogoutRequestBody
}

// ========== Response Structures ==========

// TokenResponse contains authentication tokens
type TokenResponse struct {
	AccessToken      string    `json:"access_token"`
	RefreshToken     string    `json:"refresh_token"`
	TokenType        string    `json:"token_type"`
	ExpiresIn        int64     `json:"expires_in"`
	ExpiresAt        time.Time `json:"expires_at"`
	RefreshExpiresAt time.Time `json:"refresh_expires_at"`
}

// UserInfo contains basic user information returned with tokens
type UserInfo struct {
	ID          string   `json:"id"`
	Username    string   `json:"username"`
	Email       string   `json:"email"`
	DisplayName string   `json:"display_name"`
	Roles       []string `json:"roles"`
}

// LoginResponse login response
type LoginResponse struct {
	Message string        `json:"message"`
	Token   TokenResponse `json:"token"`
	User    *UserInfo     `json:"user,omitempty"`
}

// RefreshResponse refresh response
type RefreshResponse struct {
	Message string        `json:"message"`
	Token   TokenResponse `json:"token"`
}

// LogoutResponse logout response
type LogoutResponse struct {
	Message string `json:"message"`
}
