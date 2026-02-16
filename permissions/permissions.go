package permissions

import (
	"github.com/weedbox/privy"
)

// Standard actions for CRUD operations
var (
	ActionCreate = privy.DefineAction("create", "Create", "Create a new resource")
	ActionRead   = privy.DefineAction("read", "Read", "Read resource details")
	ActionUpdate = privy.DefineAction("update", "Update", "Update an existing resource")
	ActionDelete = privy.DefineAction("delete", "Delete", "Delete a resource")
	ActionList   = privy.DefineAction("list", "List", "List resources")
)

// CRUDActions returns standard CRUD actions
func CRUDActions() []privy.Action {
	return []privy.Action{
		ActionCreate,
		ActionRead,
		ActionUpdate,
		ActionDelete,
		ActionList,
	}
}

// Resource keys
const (
	ResourceUser = "user"
	ResourceAuth = "auth"
	ResourceRole = "role"
)

// GetBuiltinResourceConfigs returns builtin resource configurations for user and auth
func GetBuiltinResourceConfigs() []privy.ResourceConfig {
	return []privy.ResourceConfig{
		// User management
		{
			Key:         ResourceUser,
			Name:        "User",
			Description: "User management",
			Actions:     CRUDActions(),
			SubResources: []privy.Resource{
				{
					Key:         "password",
					Name:        "Password",
					Description: "User password management",
					Actions: []privy.Action{
						privy.DefineAction("update", "Update Password", "Update user password"),
					},
				},
			},
		},

		// Role management
		{
			Key:         ResourceRole,
			Name:        "Role",
			Description: "Role management",
			Actions:     CRUDActions(),
		},

		// Authentication
		{
			Key:         ResourceAuth,
			Name:        "Authentication",
			Description: "Authentication operations",
			Actions: []privy.Action{
				privy.DefineAction("login", "Login", "User login"),
				privy.DefineAction("logout", "Logout", "User logout"),
				privy.DefineAction("refresh", "Refresh", "Refresh token"),
			},
		},
	}
}

// GetBuiltinDefaultRoles returns builtin default role configurations
func GetBuiltinDefaultRoles() map[string]privy.RoleConfig {
	return map[string]privy.RoleConfig{
		"admin": {
			Name:        "Administrator",
			Description: "Full system access",
			Permissions: []string{
				"*", // Full access to all resources
			},
		},
		"user": {
			Name:        "User",
			Description: "Standard user access",
			Permissions: []string{
				"auth.login",
				"auth.logout",
				"auth.refresh",
				"user.read",
				"user.password.update",
			},
		},
	}
}

// MergeResourceConfigs merges builtin resource configs with extra ones
func MergeResourceConfigs(extra ...[]privy.ResourceConfig) []privy.ResourceConfig {
	result := GetBuiltinResourceConfigs()
	for _, configs := range extra {
		result = append(result, configs...)
	}
	return result
}

// MergeDefaultRoles merges builtin default roles with extra ones
func MergeDefaultRoles(extra ...map[string]privy.RoleConfig) map[string]privy.RoleConfig {
	result := GetBuiltinDefaultRoles()
	for _, roles := range extra {
		for key, config := range roles {
			result[key] = config
		}
	}
	return result
}

// Permission string helpers
const (
	// User permissions
	PermUserCreate         = "user.create"
	PermUserRead           = "user.read"
	PermUserUpdate         = "user.update"
	PermUserDelete         = "user.delete"
	PermUserList           = "user.list"
	PermUserPasswordUpdate = "user.password.update"

	// Role permissions
	PermRoleCreate = "role.create"
	PermRoleRead   = "role.read"
	PermRoleUpdate = "role.update"
	PermRoleDelete = "role.delete"
	PermRoleList   = "role.list"

	// Auth permissions
	PermAuthLogin   = "auth.login"
	PermAuthLogout  = "auth.logout"
	PermAuthRefresh = "auth.refresh"
)
