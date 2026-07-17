# user-modules

A collection of reusable [weedbox](https://github.com/weedbox/weedbox) modules for user management, authentication, and role-based access control (RBAC). Built on top of [Uber Fx](https://github.com/uber-go/fx) for dependency injection.

## Features

- **User Management** — CRUD operations with bcrypt password hashing, UUID v7 IDs, and pagination/search via [queryhelper](https://github.com/weedbox/queryhelper)
- **Authentication** — JWT access tokens + database-backed refresh tokens with automatic rotation
- **Access Keys** — Self-service API keys (hash-only storage, optional expiry) that external programs exchange for standard token pairs
- **RBAC** — Role-based access control powered by [privy](https://github.com/weedbox/privy), with builtin roles (admin, user)
- **REST APIs** — Ready-to-use Gin HTTP handlers for user and auth endpoints
- **Extensible Permissions** — Builtin user/auth permissions with a merge API to add your own resources and roles
- **Optional Global Middleware** — Drop-in token validation middleware for your HTTP server

## Installation

```bash
go get github.com/weedbox/user-modules
```

## Module Overview

| Module | Import Path | Description |
|--------|-------------|-------------|
| [permissions](permissions/) | `github.com/weedbox/user-modules/permissions` | Builtin permission definitions and extension API |
| [rbac](rbac/) | `github.com/weedbox/user-modules/rbac` | RBAC manager with privy integration |
| [user](user/) | `github.com/weedbox/user-modules/user` | User CRUD, password hashing, authentication |
| [auth](auth/) | `github.com/weedbox/user-modules/auth` | JWT token management and middleware |
| [access_key](access_key/) | `github.com/weedbox/user-modules/access_key` | User-owned API access keys (hash-only storage, optional expiry) |
| [user_apis](user_apis/) | `github.com/weedbox/user-modules/user_apis` | REST API handlers for user management |
| [auth_apis](auth_apis/) | `github.com/weedbox/user-modules/auth_apis` | REST API handlers for login/refresh/logout |
| [role_apis](role_apis/) | `github.com/weedbox/user-modules/role_apis` | REST API handlers for role/resource management |
| [access_key_apis](access_key_apis/) | `github.com/weedbox/user-modules/access_key_apis` | REST API handlers for access key management and token exchange |
| [http_token_validator](http_token_validator/) | `github.com/weedbox/user-modules/http_token_validator` | Optional global auth middleware |

## Quick Start

### Loading Modules

A weedbox application loads modules in three phases via `modules.go`. Add user-modules in the `loadModules()` phase alongside your infrastructure modules:

```go
import (
    "github.com/weedbox/user-modules/auth"
    "github.com/weedbox/user-modules/auth_apis"
    "github.com/weedbox/user-modules/http_token_validator"
    "github.com/weedbox/user-modules/rbac"
    "github.com/weedbox/user-modules/role_apis"
    "github.com/weedbox/user-modules/user"
    "github.com/weedbox/user-modules/user_apis"
)

// loadModules - Phase 2: Infrastructure and application modules
func loadModules() ([]fx.Option, error) {
    modules := []fx.Option{
        // Infrastructure
        http_server.Module("http_server"),
        sqlite_connector.Module("database"),

        // User modules
        user.Module("user"),
        rbac.Module("rbac"),
        auth.Module("auth"),

        // API modules
        http_token_validator.Module("http_token_validator"),
        user_apis.Module("user_apis"),
        auth_apis.Module("auth_apis"),
        role_apis.Module("role_apis"),
    }
    return modules, nil
}
```

This gives you:

- A default `admin` user (username: `admin`, password: `1qaz@WSX`)
- Two builtin roles: `admin`, `user`
- JWT-based authentication with access/refresh token pairs
- REST API endpoints for user management and authentication
- Global token validation on all HTTP routes

### Configuration

All modules read configuration via [Viper](https://github.com/spf13/viper). Configuration is loaded from `config.toml` (placed in the current directory or `./configs/`). Keys are scoped by the module's scope name (e.g., `auth.jwt_secret` when scope is `"auth"`).

Example `config.toml`:

```toml
[database]
path = "data.db"

[http_server]
host = "0.0.0.0"
port = 8080

[user]
bcrypt_cost = 12
min_password_length = 8
create_default_admin = true
default_admin_password = "your-secure-password"

[rbac]
init_default_roles = true

[auth]
jwt_secret = "your-production-secret-key"
access_token_expiry = "15m"
refresh_token_expiry = "168h"
issuer = "my-app"
```

Environment variables override config file settings (prefix set in `configs.NewConfig()`):

```bash
export MYAPP_AUTH_JWT_SECRET=your-production-secret-key
export MYAPP_HTTP_SERVER_PORT=8080
```

## API Endpoints

### Authentication (`auth_apis`)

| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| POST | `/apis/v1/auth/login` | Public | Login with username/email and password |
| POST | `/apis/v1/auth/refresh` | Public | Refresh tokens using a refresh token |
| POST | `/apis/v1/auth/logout` | Public | Revoke a refresh token |

### Access Keys (`access_key_apis`)

| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| GET | `/apis/v1/me/access-keys` | Authenticated | List own access keys (metadata only) |
| POST | `/apis/v1/me/access-key` | Authenticated | Create an access key; plaintext returned once |
| DELETE | `/apis/v1/me/access-key/:id` | Authenticated | Delete own access key |
| POST | `/apis/v1/auth/access-key` | Public | Exchange a plaintext access key for a token pair |

### Self-Service (`user_apis`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/apis/v1/me` | Authenticated | Get own user information |
| PUT | `/apis/v1/me` | Authenticated | Update own information (cannot change roles/status) |
| PUT | `/apis/v1/me/password` | Authenticated | Change own password (requires current password) |

### User Management (`user_apis`)

| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| GET | `/apis/v1/users` | `user.list` | List users with pagination/search |
| POST | `/apis/v1/user` | `user.create` | Create a new user |
| GET | `/apis/v1/user/:id` | `user.read` | Get user details |
| PUT | `/apis/v1/user/:id` | `user.update` | Update user information |
| DELETE | `/apis/v1/user/:id` | `user.delete` | Delete a user |
| PUT | `/apis/v1/user/:id/password` | `user.update` | Admin reset user password (no current password required) |
| POST | `/apis/v1/user/authenticate` | `user.read` | Authenticate credentials |

### Role Management (`role_apis`)

| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| GET | `/apis/v1/roles` | `role.list` | List all roles |
| POST | `/apis/v1/role` | `role.create` | Create a new role |
| GET | `/apis/v1/role/:key` | `role.read` | Get role by key |
| PUT | `/apis/v1/role/:key` | `role.update` | Update a role |
| DELETE | `/apis/v1/role/:key` | `role.delete` | Delete a role |
| POST | `/apis/v1/role/:key/permissions` | `role.update` | Assign permissions to a role |
| DELETE | `/apis/v1/role/:key/permissions` | `role.update` | Remove permissions from a role |
| GET | `/apis/v1/resources` | `role.read` | List all resources (permission catalog) |
| GET | `/apis/v1/resource/*path` | `role.read` | Get resource details by path |

### Example: Login

```bash
curl -X POST http://localhost:8080/apis/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"identifier": "admin", "password": "1qaz@WSX"}'
```

Response:

```json
{
  "message": "Login successful",
  "token": {
    "access_token": "eyJhbGciOi...",
    "refresh_token": "base64-encoded-token",
    "token_type": "Bearer",
    "expires_in": 900,
    "expires_at": "2025-01-01T00:15:00Z",
    "refresh_expires_at": "2025-01-08T00:00:00Z"
  },
  "user": {
    "id": "...",
    "username": "admin",
    "email": "admin@localhost",
    "display_name": "System Administrator",
    "roles": ["admin"]
  }
}
```

### Example: Authenticated Request

```bash
curl http://localhost:8080/apis/v1/users \
  -H "Authorization: Bearer eyJhbGciOi..."
```

## Extending Permissions

The builtin permissions cover `user` and `auth` resources. To add your own resources and roles, use the Option pattern on `rbac.Module`:

```go
import (
    "github.com/weedbox/privy"
    "github.com/weedbox/user-modules/permissions"
    "github.com/weedbox/user-modules/rbac"
)

// Define your custom resources
func myResources() []privy.ResourceConfig {
    return []privy.ResourceConfig{
        {
            Key:         "product",
            Name:        "Product",
            Description: "Product management",
            Actions:     permissions.CRUDActions(),
        },
        {
            Key:         "order",
            Name:        "Order",
            Description: "Order management",
            Actions:     permissions.CRUDActions(),
        },
    }
}

// Define your custom roles
func myRoles() map[string]privy.RoleConfig {
    return map[string]privy.RoleConfig{
        "operator": {
            Name:        "Operator",
            Description: "Can manage products and orders",
            Permissions: []string{"product.*", "order.*"},
        },
    }
}

// Register with extra resources and roles
rbac.Module("rbac",
    rbac.WithResourceConfigs(myResources()),
    rbac.WithDefaultRoles(myRoles()),
)
```

The extra resources and roles are **merged** with the builtins — you always get the builtin resources (`user`, `auth`) and roles (`admin`, `user`) plus whatever you add.

## Module Dependency Graph

```
database.DatabaseConnector (from common-modules)
    |
    +---> user.UserManager
    |         |
    +---> rbac.RBACManager
    |         |
    +---> access_key.AccessKeyManager
    |         |
    +---> auth.AuthManager <--- user.UserManager + rbac.RBACManager
              |
              +---> user_apis (+ http_server + user.UserManager)
              +---> auth_apis (+ http_server)
              +---> role_apis (+ http_server + rbac.RBACManager)
              +---> access_key_apis (+ http_server + access_key.AccessKeyManager)
              +---> http_token_validator (+ http_server) [optional]
```

## Authentication Flow

```
Client                    Server
  |                         |
  |-- POST /auth/login ---->|  (username + password)
  |<-- access + refresh ----|
  |                         |
  |-- GET /users ---------->|  (Authorization: Bearer <access_token>)
  |   [authenticate MW]     |  -> validates JWT, sets X-User-Info header
  |   [require_permission]  |  -> reads X-User-Info, checks RBAC
  |<-- 200 OK --------------|
  |                         |
  |-- POST /auth/refresh -->|  (refresh_token)
  |<-- new access+refresh --|  (old refresh token is revoked)
  |                         |
  |-- POST /auth/logout --->|  (refresh_token)
  |<-- 200 OK --------------|  (refresh token is revoked)
```

The two-layer middleware design (`authenticate` + `require_permission`) supports ingress/gateway architectures where token validation happens at the edge and user info is forwarded via the `X-User-Info` header.

## Swagger / OpenAPI Integration

All API handler functions include [swaggo/swag](https://github.com/swaggo/swag) annotations. Downstream projects can generate a complete Swagger/OpenAPI spec without writing any extra annotations.

### Step 1: Add General API Info

In your downstream project's `main.go` (or any file parsed by `swag init`), add the general API info comments:

```go
//	@title			My Application API
//	@version		1.0
//	@description	API documentation for my application

//	@securityDefinitions.apikey	BearerAuth
//	@in							header
//	@name						Authorization
//	@description				Enter your bearer token as: Bearer <token>

func main() {
    // ...
}
```

### Step 2: Generate Swagger Docs

```bash
swag init --parseDependency --parseDependencyLevel 3
```

This scans all dependency packages (including `user-modules`) and generates `docs/swagger.json`, `docs/swagger.yaml`, and `docs/docs.go`.

### Step 3: Serve Swagger UI

```go
import (
    _ "your-project/docs" // generated docs package
    swaggerFiles "github.com/swaggo/files"
    ginSwagger "github.com/swaggo/gin-swagger"
)

// Register Swagger UI route
router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
```

Then visit `http://localhost:8080/swagger/index.html` to browse the API documentation.

## License

Apache License 2.0
