package auth

import (
	"time"
)

// TokenPair contains both access and refresh tokens
type TokenPair struct {
	AccessToken      string    `json:"access_token"`
	RefreshToken     string    `json:"refresh_token"`
	TokenType        string    `json:"token_type"`
	ExpiresIn        int64     `json:"expires_in"`          // Access token expiry in seconds
	ExpiresAt        time.Time `json:"expires_at"`          // Access token expiry timestamp
	RefreshExpiresAt time.Time `json:"refresh_expires_at"`  // Refresh token expiry timestamp
}

// AccessTokenClaims represents the claims in an access token
type AccessTokenClaims struct {
	UserID      string   `json:"user_id"`
	Username    string   `json:"username"`
	Email       string   `json:"email"`
	Roles       []string `json:"roles"`
	DisplayName string   `json:"display_name"`
}

// RefreshTokenInfo contains information about a refresh token
type RefreshTokenInfo struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	ExpiresAt time.Time `json:"expires_at"`
	Revoked   bool      `json:"revoked"`
	CreatedAt time.Time `json:"created_at"`
}

// AuthConfig contains configuration for authentication
type AuthConfig struct {
	// JWT secret key for signing tokens
	JWTSecret string

	// Access token expiration duration
	AccessTokenExpiry time.Duration

	// Refresh token expiration duration
	RefreshTokenExpiry time.Duration

	// Token issuer
	Issuer string
}
