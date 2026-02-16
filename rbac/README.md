# rbac

A weedbox module that provides role-based access control (RBAC) powered by [privy](https://github.com/weedbox/privy). Supports extensible resource and role definitions via the Option pattern.

## Overview

The RBAC module manages permission resources and roles using database-backed storage (via GORM). On startup, it:

1. Initializes the privy GORM storage (creates tables if needed)
2. Registers builtin resources (`user`, `auth`) plus any user-provided extra resources
3. Creates builtin roles (`admin`, `user`) plus any user-provided extra roles (if enabled)

## Dependencies

| Dependency | Source | Description |
|------------|--------|-------------|
| `database.DatabaseConnector` | `common-modules` | GORM database connection |

## Module Registration

### Basic Usage

```go
rbac.Module("rbac")
```

### With Custom Resources and Roles

```go
import (
    "github.com/weedbox/privy"
    "github.com/weedbox/user-modules/permissions"
    "github.com/weedbox/user-modules/rbac"
)

rbac.Module("rbac",
    rbac.WithResourceConfigs([]privy.ResourceConfig{
        {
            Key:         "product",
            Name:        "Product",
            Description: "Product management",
            Actions:     permissions.CRUDActions(),
        },
    }),
    rbac.WithDefaultRoles(map[string]privy.RoleConfig{
        "operator": {
            Name:        "Operator",
            Description: "Product operator",
            Permissions: []string{"product.*"},
        },
    }),
)
```

Custom resources and roles are **merged** with the builtins. If a custom role key matches a builtin key (e.g., `"admin"`), the custom definition takes precedence.

## Configuration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `init_default_roles` | `bool` | `true` | Whether to create default roles on startup |

## Options

| Option | Description |
|--------|-------------|
| `WithResourceConfigs(configs []privy.ResourceConfig)` | Extra resource definitions to merge with builtins |
| `WithDefaultRoles(roles map[string]privy.RoleConfig)` | Extra role definitions to merge with builtins |

## API Reference

### RBACManager Methods

**Permission Checking:**

| Method | Signature | Description |
|--------|-----------|-------------|
| `CheckPermission` | `(roleKey, permission string) (bool, error)` | Check if a single role has a permission |
| `CheckPermissions` | `(roleKeys []string, permission string) (bool, error)` | Check if any role in a list has a permission |

**Role Management:**

| Method | Signature | Description |
|--------|-----------|-------------|
| `CreateRole` | `(key string, config privy.RoleConfig) (*privy.Role, error)` | Create a new role |
| `GetRole` | `(key string) (*privy.Role, error)` | Get a role by key |
| `ListRoles` | `() ([]privy.Role, error)` | List all roles |
| `DeleteRole` | `(key string) error` | Delete a role |
| `AssignPermissions` | `(roleKey string, permissions []string) error` | Add permissions to a role |
| `RemovePermissions` | `(roleKey string, permissions []string) error` | Remove permissions from a role |

**Resource Management:**

| Method | Signature | Description |
|--------|-----------|-------------|
| `GetResource` | `(path string) (*privy.Resource, error)` | Get a resource by path |
| `ListResources` | `() ([]privy.Resource, error)` | List all top-level resources |
| `GetManager` | `() *privy.Manager` | Get the underlying privy manager |

## Example: Runtime Permission Check

```go
// In your handler or service
allowed, err := rbacManager.CheckPermissions(userRoles, "product.create")
if err != nil {
    // handle error
}
if !allowed {
    // return 403
}
```
