package auth

import "errors"

var (
	// ErrInvalidCredentials indicates invalid username/email or password
	ErrInvalidCredentials = errors.New("invalid credentials")

	// ErrInvalidToken indicates the token is invalid or malformed
	ErrInvalidToken = errors.New("invalid token")

	// ErrTokenExpired indicates the token has expired
	ErrTokenExpired = errors.New("token expired")

	// ErrTokenRevoked indicates the refresh token has been revoked
	ErrTokenRevoked = errors.New("token revoked")

	// ErrTokenNotFound indicates the refresh token was not found
	ErrTokenNotFound = errors.New("token not found")

	// ErrUserInactive indicates the user account is not active
	ErrUserInactive = errors.New("user account is not active")

	// ErrOperationFailed indicates a general operation failure
	ErrOperationFailed = errors.New("operation failed")
)
