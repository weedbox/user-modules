package models

import (
	"time"
)

type AccessKey struct {
	ID     string `gorm:"type:varchar(36);primaryKey" json:"id"`
	UserID string `gorm:"type:varchar(36);not null;index:idx_access_keys_user_id" json:"user_id"`
	Name   string `gorm:"type:varchar(255);not null" json:"name"`
	// Prefix is the leading fragment of the plaintext key (e.g. "ak_Ab12Cd34"),
	// stored for display purposes only. It is not sufficient to recover the key.
	Prefix string `gorm:"type:varchar(32);not null" json:"prefix"`
	// SecretHash is the SHA-256 (hex) of the full plaintext key. The plaintext is
	// returned once at creation time and never persisted.
	SecretHash string     `gorm:"type:varchar(64);not null;uniqueIndex:idx_access_keys_secret_hash" json:"-"`
	ExpiresAt  *time.Time `json:"expires_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	CreatedAt  time.Time  `gorm:"index" json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

func (AccessKey) TableName() string {
	return "access_keys"
}
