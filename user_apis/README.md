# user_apis

A weedbox module that registers REST API endpoints for user management. Provides Gin HTTP handlers for CRUD operations, password management, and user authentication.

## Overview

On startup, this module registers the following routes under `/apis/v1` on the HTTP server. All routes (except authenticate) are protected by RBAC permission checks.

## Dependencies

| Dependency | Source | Description |
|------------|--------|-------------|
| `http_server.HTTPServer` | `common-modules` | Gin HTTP server for route registration |
| `user.UserManager` | `user-modules/user` | User business logic |
| `auth.AuthManager` | `user-modules/auth` | Permission middleware |

## Module Registration

```go
user_apis.Module("user_apis")
```

## Endpoints

All endpoints are prefixed with `/apis/v1`.

### List Users

```
GET /apis/v1/users
```

**Permission:** `user.list`

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `page` | `int` | `1` | Page number |
| `page_size` | `int` | `10` | Items per page |
| `keywords` | `string` | | Search text (searches username, email, display_name) |
| `search_fields` | `string` | | Comma-separated fields to search |
| `orderby` | `string` | | Comma-separated fields to order by |
| `order` | `int` | `-1` | Sort order: `1` = ascending, `-1` = descending |
| `status` | `string` | | Filter by status (`active`, `inactive`, `suspended`) |
| `role` | `string` | | Filter by role |

**Response:**

```json
{
  "total": 25,
  "page": 1,
  "page_size": 10,
  "total_pages": 3,
  "order_by": ["created_at"],
  "order": -1,
  "keywords": "",
  "users": [
    {
      "id": "...",
      "username": "admin",
      "email": "admin@localhost",
      "display_name": "System Administrator",
      "roles": ["admin"],
      "status": "active",
      "last_login_at": "2025-01-01T00:00:00Z",
      "created_at": "2025-01-01T00:00:00Z",
      "updated_at": "2025-01-01T00:00:00Z"
    }
  ]
}
```

### Create User

```
POST /apis/v1/user
```

**Permission:** `user.create`

**Request Body:**

```json
{
  "username": "john",
  "email": "john@example.com",
  "password": "secure-password",
  "display_name": "John Doe",
  "roles": ["user"],
  "status": "active"
}
```

| Field | Required | Validation | Description |
|-------|----------|------------|-------------|
| `username` | Yes | min=3, max=255 | Unique username |
| `email` | Yes | Valid email | Unique email |
| `password` | Yes | min=8 | Password (will be hashed) |
| `display_name` | No | | Display name |
| `roles` | No | | Role keys (default: `["user"]`) |
| `status` | No | `active`/`inactive`/`suspended` | Status (default: `active`) |

**Response (201):**

```json
{
  "message": "user created successfully",
  "user": { "id": "...", "username": "john", ... }
}
```

### Get User

```
GET /apis/v1/user/:id
```

**Permission:** `user.read`

**Response (200):**

```json
{
  "user": { "id": "...", "username": "john", ... }
}
```

### Update User

```
PUT /apis/v1/user/:id
```

**Permission:** `user.update`

**Request Body:** Same fields as Create (all optional). Only non-empty fields are updated.

**Response (200):**

```json
{
  "message": "user updated successfully",
  "user": { "id": "...", "username": "john", ... }
}
```

### Delete User

```
DELETE /apis/v1/user/:id
```

**Permission:** `user.delete`

**Response (200):**

```json
{
  "message": "user deleted successfully"
}
```

### Update Password

```
PUT /apis/v1/user/:id/password
```

**Permission:** `user.password.update`

**Request Body:**

```json
{
  "current_password": "old-password",
  "new_password": "new-secure-password"
}
```

| Field | Required | Validation | Description |
|-------|----------|------------|-------------|
| `current_password` | Yes | | Current password for verification |
| `new_password` | Yes | min=8 | New password |

**Response (200):**

```json
{
  "message": "password updated successfully"
}
```

### Authenticate User

```
POST /apis/v1/user/authenticate
```

**Permission:** `user.read`

**Request Body:**

```json
{
  "identifier": "john",
  "password": "secure-password"
}
```

**Response (200):**

```json
{
  "success": true,
  "message": "Authentication successful",
  "user": { "id": "...", "username": "john", ... }
}
```

## Error Responses

All error responses follow the format:

```json
{
  "error": "Error description"
}
```

| Status | Condition |
|--------|-----------|
| `400` | Invalid request body or parameters |
| `401` | Authentication required or invalid credentials |
| `403` | Insufficient permissions |
| `404` | User not found |
| `409` | Username or email already exists |
| `500` | Internal server error |
