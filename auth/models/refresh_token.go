package models

import (
	"time"
)

// RefreshToken represents a refresh token stored in the database
type RefreshToken struct {
	ID        string    `gorm:"type:varchar(36);primary_key" json:"id"`
	UserID    string    `gorm:"type:varchar(36);not null;index:idx_refresh_token_user_id" json:"user_id"`
	Token     string    `gorm:"type:varchar(512);not null;uniqueIndex:idx_refresh_token_token" json:"token"`
	ExpiresAt time.Time `gorm:"not null;index:idx_refresh_token_expires_at" json:"expires_at"`
	Revoked   bool      `gorm:"default:false;index:idx_refresh_token_revoked" json:"revoked"`
	CreatedAt time.Time `gorm:"index" json:"created_at"`
}

// TableName specifies the table name for RefreshToken
func (RefreshToken) TableName() string {
	return "refresh_tokens"
}
