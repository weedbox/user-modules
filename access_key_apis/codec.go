package access_key_apis

import "time"

// ========== Request Structures ==========

// --- Create ---

type CreateRequestBody struct {
	Name string `json:"name" binding:"required"`
	// ExpiresAt is an RFC3339 timestamp; empty means the key never expires.
	ExpiresAt string `json:"expires_at"`
}

type CreateRequest struct {
	Body CreateRequestBody
}

// --- Delete ---

type DeleteRequestURI struct {
	ID string `uri:"id" binding:"required"`
}

type DeleteRequest struct {
	URI DeleteRequestURI
}

// --- Exchange ---

type ExchangeRequestBody struct {
	AccessKey string `json:"access_key" binding:"required"`
}

type ExchangeRequest struct {
	Body ExchangeRequestBody
}

// ========== Response Structures ==========

type AccessKeyEntry struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	Prefix     string  `json:"prefix"`
	ExpiresAt  *string `json:"expires_at"`
	LastUsedAt *string `json:"last_used_at"`
	CreatedAt  string  `json:"created_at"`
}

type CreateResponse struct {
	Message string `json:"message"`
	// Key is the plaintext, returned only once in this response. It cannot be
	// retrieved again.
	Key       string          `json:"key"`
	AccessKey *AccessKeyEntry `json:"access_key"`
}

type ListResponse struct {
	AccessKeys []*AccessKeyEntry `json:"access_keys"`
}

type DeleteResponse struct {
	Message string `json:"message"`
}

// TokenResponse mirrors the token block of /auth/login so clients can share
// one parser across both authentication flows.
type TokenResponse struct {
	AccessToken      string    `json:"access_token"`
	RefreshToken     string    `json:"refresh_token"`
	TokenType        string    `json:"token_type"`
	ExpiresIn        int64     `json:"expires_in"`
	ExpiresAt        time.Time `json:"expires_at"`
	RefreshExpiresAt time.Time `json:"refresh_expires_at"`
}

type ExchangeResponse struct {
	Message string        `json:"message"`
	Token   TokenResponse `json:"token"`
}

// ErrorResponse error response
type ErrorResponse struct {
	Error string `json:"error" example:"error message"`
}
