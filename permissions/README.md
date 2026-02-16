# permissions

Defines builtin permission resources, roles, and permission constants for the user-modules library. Provides an extension API for adding custom resources and roles.

## Overview

This package is **not** a weedbox module — it is a plain Go package that provides data definitions consumed by the `rbac` module. It defines:

- **Builtin resources**: `user` (with `password` sub-resource) and `auth`
- **Builtin roles**: `admin`, `user`
- **Permission constants**: Type-safe strings like `permissions.PermUserCreate`
- **Standard CRUD actions**: Reusable action definitions
- **Merge functions**: Combine builtin definitions with custom ones

## Builtin Resources

### user

| Action | Permission String | Description |
|--------|-------------------|-------------|
| create | `user.create` | Create a new user |
| read | `user.read` | Read user details |
| update | `user.update` | Update user information |
| delete | `user.delete` | Delete a user |
| list | `user.list` | List users |

Sub-resource: **password**

| Action | Permission String | Description |
|--------|-------------------|-------------|
| update | `user.password.update` | Update user password |

### auth

| Action | Permission String | Description |
|--------|-------------------|-------------|
| login | `auth.login` | User login |
| logout | `auth.logout` | User logout |
| refresh | `auth.refresh` | Refresh token |

## Builtin Roles

| Role | Description | Permissions |
|------|-------------|-------------|
| `admin` | Full system access | `*` (wildcard) |
| `user` | Standard user | `auth.login`, `auth.logout`, `auth.refresh`, `user.read`, `user.password.update` |

## Usage

### Permission Constants

Use the constants in your API route definitions or permission checks:

```go
import "github.com/weedbox/user-modules/permissions"

// In route registration
router.GET("/users", requirePerm(permissions.PermUserList), listHandler)
router.POST("/user", requirePerm(permissions.PermUserCreate), createHandler)
```

### Standard CRUD Actions

When defining custom resources, use `CRUDActions()` for convenience:

```go
import (
    "github.com/weedbox/privy"
    "github.com/weedbox/user-modules/permissions"
)

config := privy.ResourceConfig{
    Key:     "product",
    Name:    "Product",
    Actions: permissions.CRUDActions(), // create, read, update, delete, list
}
```

### Extending with Custom Resources

Use `MergeResourceConfigs` and `MergeDefaultRoles` to combine builtin definitions with your own:

```go
// Get builtins + your custom resources
allResources := permissions.MergeResourceConfigs(myResourceConfigs)

// Get builtins + your custom roles
allRoles := permissions.MergeDefaultRoles(myRoleConfigs)
```

These merge functions are used internally by the `rbac` module when you pass options via `rbac.WithResourceConfigs()` and `rbac.WithDefaultRoles()`.

### Retrieving Builtins Only

```go
// Get only builtin resource configs (user + auth)
resources := permissions.GetBuiltinResourceConfigs()

// Get only builtin roles (admin, user)
roles := permissions.GetBuiltinDefaultRoles()
```

## API Reference

### Functions

| Function | Returns | Description |
|----------|---------|-------------|
| `CRUDActions()` | `[]privy.Action` | Standard create/read/update/delete/list actions |
| `GetBuiltinResourceConfigs()` | `[]privy.ResourceConfig` | Builtin user + auth resource definitions |
| `GetBuiltinDefaultRoles()` | `map[string]privy.RoleConfig` | Builtin admin/user role definitions |
| `MergeResourceConfigs(extra ...[]privy.ResourceConfig)` | `[]privy.ResourceConfig` | Merge builtins with extra resources |
| `MergeDefaultRoles(extra ...map[string]privy.RoleConfig)` | `map[string]privy.RoleConfig` | Merge builtins with extra roles |

### Constants

**Resource keys:**

- `ResourceUser = "user"`
- `ResourceAuth = "auth"`

**Permission strings:**

- `PermUserCreate`, `PermUserRead`, `PermUserUpdate`, `PermUserDelete`, `PermUserList`
- `PermUserPasswordUpdate`
- `PermAuthLogin`, `PermAuthLogout`, `PermAuthRefresh`

**Action variables:**

- `ActionCreate`, `ActionRead`, `ActionUpdate`, `ActionDelete`, `ActionList`
