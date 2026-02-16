# auth

A weedbox module for JWT-based authentication. Provides login/logout, access token generation, refresh token rotation, and Gin middleware for token validation and permission checking.

## Overview

The Auth module handles:

- **Login**: Authenticates credentials via the `user` module, returns a JWT access token + database-backed refresh token
- **Token Refresh**: Validates refresh tokens and issues new token pairs (with automatic rotation — old refresh tokens are revoked)
- **Logout**: Revokes refresh tokens (single or all sessions)
- **Token Validation**: Validates JWT access tokens and extracts user claims
- **Middleware**: Two-layer Gin middleware for authentication and authorization

## Dependencies

| Dependency | Source | Description |
|------------|--------|-------------|
| `database.DatabaseConnector` | `common-modules` | GORM database connection |
| `user.UserManager` | `user-modules/user` | User authentication and lookup |
| `rbac.RBACManager` | `user-modules/rbac` | Permission checking |

## Module Registration

```go
auth.Module("auth")
```

## Configuration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `jwt_secret` | `string` | `"change-this-secret-in-production"` | HMAC secret for signing JWTs |
| `access_token_expiry` | `duration` | `"15m"` | Access token lifetime |
| `refresh_token_expiry` | `duration` | `"168h"` (7 days) | Refresh token lifetime |
| `issuer` | `string` | `"weedbox"` | JWT issuer claim |

**Important:** Always override `jwt_secret` in production.

## Data Model

The `RefreshToken` model (`auth/models/refresh_token.go`) maps to the `refresh_tokens` table:

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| `ID` | `varchar(36)` | Primary key | UUID v7 |
| `UserID` | `varchar(36)` | Not null, indexed | Owner user ID |
| `Token` | `varchar(512)` | Unique, not null | The refresh token string |
| `ExpiresAt` | `timestamp` | Not null, indexed | Expiration time |
| `Revoked` | `bool` | Default: `false` | Whether the token has been revoked |
| `CreatedAt` | `timestamp` | Indexed | Creation time |

## JWT Claims

Access tokens contain the following custom claims:

```json
{
  "iss": "weedbox",
  "sub": "user-uuid",
  "exp": 1234567890,
  "iat": 1234567890,
  "jti": "unique-token-id",
  "user_id": "user-uuid",
  "username": "admin",
  "email": "admin@localhost",
  "roles": ["admin"],
  "display_name": "System Administrator"
}
```

## API Reference

### AuthManager Methods

**Authentication:**

| Method | Signature | Description |
|--------|-----------|-------------|
| `Login` | `(ctx, identifier, password string) (*TokenPair, error)` | Authenticate and return token pair |
| `RefreshTokens` | `(ctx, refreshToken string) (*TokenPair, error)` | Refresh tokens (rotates refresh token) |
| `Logout` | `(ctx, refreshToken string) error` | Revoke a single refresh token |
| `LogoutAll` | `(ctx, userID string) error` | Revoke all refresh tokens for a user |

**Token Validation:**

| Method | Signature | Description |
|--------|-----------|-------------|
| `ValidateAccessToken` | `(tokenString string) (*AccessTokenClaims, error)` | Validate JWT and extract claims |

**Token Management:**

| Method | Signature | Description |
|--------|-----------|-------------|
| `GetActiveRefreshTokens` | `(ctx, userID string) ([]*RefreshTokenInfo, error)` | List active refresh tokens for a user |
| `CleanupExpiredTokens` | `(ctx) (int64, error)` | Remove expired/revoked tokens from DB |

**Middleware:**

| Method | Signature | Description |
|--------|-----------|-------------|
| `GetMiddleware` | `(name string) interface{}` | Get middleware by name (see below) |

### Middleware

The `GetMiddleware` method returns two types of middleware:

#### `"authenticate"` — Token Validation Middleware

Returns `gin.HandlerFunc`. This middleware:

1. Reads the `Authorization: Bearer <token>` header
2. If no token is provided, passes through (allows unauthenticated access)
3. If a token is provided, validates it and sets the `X-User-Info` header with base64-encoded session data
4. If the token is invalid or expired, returns `401 Unauthorized`

```go
authMiddleware := authManager.GetMiddleware("authenticate").(gin.HandlerFunc)
router.Use(authMiddleware)
```

#### `"require_permission"` — Permission Check Middleware

Returns `func(string) gin.HandlerFunc`. This middleware:

1. If permission is `"*"`, passes through (public endpoint)
2. Reads the `X-User-Info` header (set by the `authenticate` middleware)
3. Decodes the session and checks RBAC permissions
4. Sets session data in the Gin context for downstream handlers
5. Returns `401` if not authenticated, `403` if insufficient permissions

```go
requirePerm := authManager.GetMiddleware("require_permission").(func(string) gin.HandlerFunc)
router.GET("/users", requirePerm("user.list"), listHandler)
router.POST("/public", requirePerm("*"), publicHandler)
```

### Context Helpers

Helper functions to extract session data from the Gin context (set by `require_permission` middleware):

| Function | Signature | Description |
|----------|-----------|-------------|
| `GetSession` | `(c *gin.Context) (*Session, bool)` | Get the full session |
| `GetUserID` | `(c *gin.Context) (string, bool)` | Get the authenticated user's ID |
| `GetUsername` | `(c *gin.Context) (string, bool)` | Get the authenticated user's username |
| `GetRoles` | `(c *gin.Context) ([]string, bool)` | Get the authenticated user's roles |
| `HasRole` | `(c *gin.Context, role string) bool` | Check if user has a specific role |

### Types

**TokenPair:**

```go
type TokenPair struct {
    AccessToken      string
    RefreshToken     string
    TokenType        string    // "Bearer"
    ExpiresIn        int64     // Access token lifetime in seconds
    ExpiresAt        time.Time // Access token expiry timestamp
    RefreshExpiresAt time.Time // Refresh token expiry timestamp
}
```

**Session:**

```go
type Session struct {
    UserID      string
    Username    string
    Email       string
    Roles       []string
    DisplayName string
}
```

### Errors

| Error | Description |
|-------|-------------|
| `ErrInvalidCredentials` | Wrong username/email or password |
| `ErrInvalidToken` | Token is malformed or has an invalid signature |
| `ErrTokenExpired` | Token has expired |
| `ErrTokenRevoked` | Refresh token has been revoked |
| `ErrTokenNotFound` | Refresh token not found in database |
| `ErrUserInactive` | User account is not active |
| `ErrOperationFailed` | General operation failure |

## Architecture: Two-Layer Middleware

The middleware is split into two layers to support ingress/gateway architectures:

```
Request --> [authenticate] --> [require_permission] --> Handler
               |                      |
               v                      v
         Validates JWT          Reads X-User-Info header
         Sets X-User-Info       Checks RBAC permissions
         header                 Sets session in context
```

This design allows:

- Running `authenticate` at the gateway/ingress level
- Forwarding `X-User-Info` to backend services
- Backend services only need `require_permission` to check permissions

## Example: Using in a Custom Handler

```go
func myHandler(c *gin.Context) {
    // Get authenticated user info
    session, ok := auth.GetSession(c)
    if !ok {
        c.JSON(401, gin.H{"error": "not authenticated"})
        return
    }

    // Use session data
    fmt.Printf("User: %s (roles: %v)\n", session.Username, session.Roles)

    // Check role
    if auth.HasRole(c, "admin") {
        // admin-specific logic
    }
}
```
