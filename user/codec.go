package user

import (
	"time"

	"github.com/weedbox/queryhelper"
)

// UserConfig configuration for create/update
type UserConfig struct {
	Username    string
	Email       string
	Password    string // Plain text password (will be hashed)
	DisplayName string
	Roles       []string // Multiple roles
	Status      string
}

// ListUsersRequest filter conditions for list query
type ListUsersRequest struct {
	Username *string
	Email    *string
	Role     *string // Filter by role (checks if user has this role)
	Status   *string
}

// ListUsersResp list query response
type ListUsersResp struct {
	Data        []*User
	QueryHelper *queryhelper.QueryHelper
}

// User public user structure (password hash is never exposed)
type User struct {
	ID          string
	Username    string
	Email       string
	DisplayName string
	Roles       []string
	Status      string
	LastLoginAt *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// QueryHelper settings
var DefaultQuerySettings = &queryhelper.QuerySettings{
	AllowedOrderBy: []string{"created_at", "updated_at", "username", "email", "last_login_at"},
	AllowedSearch:  []string{"username", "email", "display_name"},
	AllowedFilters: map[string][]string{
		"status":   {"=", "!=", "IN"},
		"role":     {"=", "!=", "IN"},
		"username": {"=", "LIKE"},
		"email":    {"=", "LIKE"},
	},
}
