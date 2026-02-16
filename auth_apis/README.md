# auth_apis

A weedbox module that registers REST API endpoints for authentication. Provides Gin HTTP handlers for login, token refresh, and logout.

## Overview

On startup, this module registers authentication routes under `/apis/v1/auth` on the HTTP server. All endpoints are public (permission `"*"`) since they handle unauthenticated or token-based access.

## Dependencies

| Dependency | Source | Description |
|------------|--------|-------------|
| `http_server.HTTPServer` | `common-modules` | Gin HTTP server for route registration |
| `auth.AuthManager` | `user-modules/auth` | Authentication business logic |

## Module Registration

```go
auth_apis.Module("auth_apis")
```

## Endpoints

All endpoints are prefixed with `/apis/v1/auth`.

### Login

```
POST /apis/v1/auth/login
```

**Permission:** Public (no authentication required)

Authenticate with username or email and password. Returns a JWT access token and a refresh token.

**Request Body:**

```json
{
  "identifier": "admin",
  "password": "1qaz@WSX"
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `identifier` | Yes | Username or email |
| `password` | Yes | Password |

**Response (200):**

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

**Error Responses:**

| Status | Condition |
|--------|-----------|
| `400` | Missing or invalid request body |
| `401` | Invalid credentials |
| `403` | User account is not active |
| `500` | Internal server error |

### Refresh Tokens

```
POST /apis/v1/auth/refresh
```

**Permission:** Public

Exchange a valid refresh token for a new access token and refresh token. The old refresh token is automatically revoked (token rotation).

**Request Body:**

```json
{
  "refresh_token": "base64-encoded-token"
}
```

**Response (200):**

```json
{
  "message": "Token refreshed successfully",
  "token": {
    "access_token": "eyJhbGciOi...",
    "refresh_token": "new-base64-encoded-token",
    "token_type": "Bearer",
    "expires_in": 900,
    "expires_at": "2025-01-01T00:15:00Z",
    "refresh_expires_at": "2025-01-08T00:00:00Z"
  }
}
```

**Error Responses:**

| Status | Condition |
|--------|-----------|
| `400` | Missing or invalid request body |
| `401` | Invalid, expired, or revoked refresh token |
| `403` | User account is not active |
| `500` | Internal server error |

### Logout

```
POST /apis/v1/auth/logout
```

**Permission:** Public

Revoke a refresh token to end the session.

**Request Body:**

```json
{
  "refresh_token": "base64-encoded-token"
}
```

**Response (200):**

```json
{
  "message": "Logged out successfully"
}
```

**Error Responses:**

| Status | Condition |
|--------|-----------|
| `400` | Missing or invalid request body |
| `404` | Refresh token not found |
| `500` | Internal server error |

## Authentication Flow

```
1. Client sends POST /auth/login with credentials
2. Server validates credentials and returns access_token + refresh_token
3. Client uses access_token in Authorization header for subsequent requests
4. When access_token expires, client sends POST /auth/refresh with refresh_token
5. Server revokes old refresh_token, issues new access_token + refresh_token
6. To log out, client sends POST /auth/logout with refresh_token
```

## Security Notes

- **Token Rotation:** Each refresh operation revokes the old refresh token and issues a new one. This limits the window of exposure if a refresh token is compromised.
- **Public Endpoints:** All auth endpoints are public by design — login requires no prior authentication, and refresh/logout validate security through the refresh token itself.
- **Inactive Users:** If a user's status is not `active`, login and refresh will be rejected with `403 Forbidden`.
