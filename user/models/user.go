package models

import (
	"time"
)

// User represents a user in the system
type User struct {
	ID           string     `gorm:"type:varchar(36);primary_key" json:"id"`
	Username     string     `gorm:"type:varchar(255);not null;uniqueIndex:idx_user_username" json:"username"`
	Email        string     `gorm:"type:varchar(255);uniqueIndex:idx_user_email" json:"email"`
	PasswordHash string     `gorm:"type:varchar(255);not null" json:"-"` // bcrypt hash (includes salt)
	DisplayName  string     `gorm:"type:varchar(255)" json:"display_name"`
	Roles        []string   `gorm:"type:text;serializer:json" json:"roles"` // Multiple roles stored as JSON array
	Status       string     `gorm:"type:varchar(50);default:'active';index:idx_user_status" json:"status"`
	LastLoginAt  *time.Time `gorm:"index:idx_user_last_login" json:"last_login_at"`
	CreatedAt    time.Time  `gorm:"index" json:"created_at"`
	UpdatedAt    time.Time  `gorm:"index" json:"updated_at"`
}

// TableName specifies the table name
func (User) TableName() string {
	return "users"
}
