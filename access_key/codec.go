package access_key

import (
	"time"
)

type AccessKey struct {
	ID         string
	UserID     string
	Name       string
	Prefix     string
	ExpiresAt  *time.Time
	LastUsedAt *time.Time
	CreatedAt  time.Time
	UpdatedAt  time.Time
}
