package user

import "errors"

var (
	ErrNotFound           = errors.New("user not found")
	ErrUsernameExists     = errors.New("username already exists")
	ErrEmailExists        = errors.New("email already exists")
	ErrInvalidInput       = errors.New("invalid input")
	ErrInvalidPassword    = errors.New("invalid password")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrOperationFailed    = errors.New("operation failed")
	ErrPasswordTooShort   = errors.New("password must be at least 8 characters")
)
