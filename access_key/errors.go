package access_key

import "errors"

var (
	ErrNotFound     = errors.New("access key not found")
	ErrInvalidInput = errors.New("invalid input")
	// ErrInvalidKey means the key is malformed or unknown. Callers should map
	// both cases to the same 401 response so attackers cannot distinguish a
	// bad format from a non-existent key.
	ErrInvalidKey = errors.New("invalid access key")
	ErrKeyExpired = errors.New("access key expired")
)
