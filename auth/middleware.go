package auth

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	// HeaderAuthorization is the Authorization header name
	HeaderAuthorization = "Authorization"

	// HeaderUserInfo is the header name for passing user info (for ingress integration)
	HeaderUserInfo = "X-User-Info"

	// HeaderGatewaySecret is an optional shared-secret header proving a request
	// originated from the trusted gateway. Only consulted in gateway mode when
	// trusted_header_secret is configured.
	HeaderGatewaySecret = "X-Gateway-Secret"

	// ContextKeySession is the key for storing session info in gin context
	ContextKeySession = "auth_session"

	// ContextKeyUserID is the key for storing user ID in gin context
	ContextKeyUserID = "auth_user_id"

	// ContextKeyUsername is the key for storing username in gin context
	ContextKeyUsername = "auth_username"

	// ContextKeyRoles is the key for storing user roles in gin context
	ContextKeyRoles = "auth_roles"
)

const (
	// ModeStandalone: this service is the sole authority on identity. It validates the
	// JWT itself and NEVER trusts a client-supplied X-User-Info header (any inbound copy
	// is stripped before processing). This is the secure default.
	ModeStandalone = "standalone"

	// ModeGateway: a trusted upstream (API gateway / service mesh) validates the token and
	// injects X-User-Info; this service trusts that header. Only safe when the service is
	// reachable exclusively through that gateway and the gateway strips client-supplied
	// X-User-Info. Optionally hardened with trusted_header_secret (see HeaderGatewaySecret).
	ModeGateway = "gateway"
)

// Session represents the authenticated user session
type Session struct {
	UserID      string   `json:"user_id"`
	Username    string   `json:"username"`
	Email       string   `json:"email"`
	Roles       []string `json:"roles"`
	DisplayName string   `json:"display_name"`
}

// MiddlewareFunc is the type for middleware functions
type MiddlewareFunc = gin.HandlerFunc

// MiddlewareWithParamFunc is the type for middleware functions that accept parameters
type MiddlewareWithParamFunc = func(param string) gin.HandlerFunc

// GetMiddleware returns a middleware by name
// Supported middlewares:
//   - "authenticate": validates JWT token and sets X-User-Info header
//   - "require_permission": reads X-User-Info header and sets session in context
func (m *AuthManager) GetMiddleware(name string) interface{} {
	switch name {
	case "authenticate":
		return m.authenticateMiddleware()
	case "require_permission":
		return m.requirePermissionMiddleware
	default:
		return nil
	}
}

// authenticateMiddleware validates JWT token and sets user info in header
// This middleware:
// 1. Establishes trust in the X-User-Info header according to the configured mode:
//    - standalone: strips any inbound (client-supplied) X-User-Info; identity may only
//      come from a token this service validates below.
//    - gateway: keeps the inbound X-User-Info (injected by a trusted upstream); when a
//      trusted_header_secret is configured, only keeps it if X-Gateway-Secret matches.
// 2. Extracts JWT token from Authorization header (Bearer token)
// 3. If no token provided, passes through (identity, if any, is the trusted X-User-Info)
// 4. If token provided, validates and sets X-User-Info header from the token
// 5. If token is invalid/expired, returns 401 error
func (m *AuthManager) authenticateMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Establish trust in any inbound X-User-Info before anything reads it.
		if m.authMode != ModeGateway {
			// standalone: never trust a client-supplied identity header.
			c.Request.Header.Del(HeaderUserInfo)
		} else if m.trustedHeaderSecret != "" {
			// gateway with caller verification: only honor the forwarded identity when the
			// request proves it came from the trusted gateway; otherwise strip it.
			got := c.GetHeader(HeaderGatewaySecret)
			if subtle.ConstantTimeCompare([]byte(got), []byte(m.trustedHeaderSecret)) != 1 {
				c.Request.Header.Del(HeaderUserInfo)
			}
		}

		// Get Authorization header
		authHeader := c.GetHeader(HeaderAuthorization)
		if authHeader == "" {
			// No token provided, pass through
			c.Next()
			return
		}

		// Check Bearer prefix
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid authorization header format, expected 'Bearer <token>'",
			})
			return
		}

		tokenString := parts[1]

		// Validate token
		claims, err := m.ValidateAccessToken(tokenString)
		if err != nil {
			switch err {
			case ErrTokenExpired:
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error": "Token has expired",
				})
			default:
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error": "Invalid token",
				})
			}
			return
		}

		// Create session from claims
		session := &Session{
			UserID:      claims.UserID,
			Username:    claims.Username,
			Email:       claims.Email,
			Roles:       claims.Roles,
			DisplayName: claims.DisplayName,
		}

		// Encode session as base64 JSON for header
		sessionJSON, err := json.Marshal(session)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to encode session",
			})
			return
		}
		sessionBase64 := base64.StdEncoding.EncodeToString(sessionJSON)

		// Set user info header (for ingress integration)
		c.Request.Header.Set(HeaderUserInfo, sessionBase64)

		// Also set in response header for debugging/transparency
		c.Header(HeaderUserInfo, sessionBase64)

		c.Next()
	}
}

// requirePermissionMiddleware reads user info from header and sets session in context
// This middleware:
// 1. If permission is "*", passes through without checking (public endpoint)
// 2. Otherwise, reads X-User-Info header and validates
// 3. Sets session and user info in gin context for handlers to use
// 4. Uses RBAC to check if user's roles have the required permission
//
// Usage: auth.GetMiddleware("require_permission")("*") for public endpoints (no auth required)
// Usage: auth.GetMiddleware("require_permission")("user.read") for specific permission
// Usage: auth.GetMiddleware("require_permission")("admin") for admin role check
func (m *AuthManager) requirePermissionMiddleware(permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// "*" means public endpoint: authentication is optional. If a trusted identity is
		// present (set by authenticateMiddleware from a token, or forwarded by a trusted
		// gateway), expose it to handlers so they can personalize; never reject when it is
		// missing or malformed.
		if permission == "*" {
			applySessionFromHeader(c, c.GetHeader(HeaderUserInfo))
			c.Next()
			return
		}

		// Get user info header
		userInfoHeader := c.GetHeader(HeaderUserInfo)
		if userInfoHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Authentication required",
			})
			return
		}

		// Decode base64
		sessionJSON, err := base64.StdEncoding.DecodeString(userInfoHeader)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid user info header",
			})
			return
		}

		// Parse JSON
		var session Session
		if err := json.Unmarshal(sessionJSON, &session); err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid user info format",
			})
			return
		}

		// Check permission using RBAC
		if permission != "" {
			allowed, err := m.Params().RBAC.CheckPermissions(session.Roles, permission)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"error": "Failed to check permissions",
				})
				return
			}
			if !allowed {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"error": "Insufficient permissions",
				})
				return
			}
		}

		// Set session in context
		c.Set(ContextKeySession, &session)
		c.Set(ContextKeyUserID, session.UserID)
		c.Set(ContextKeyUsername, session.Username)
		c.Set(ContextKeyRoles, session.Roles)

		c.Next()
	}
}

// applySessionFromHeader best-effort decodes X-User-Info and stores the identity in the
// gin context. Returns false when the header is absent or malformed. Used for optional
// authentication on public ("*") endpoints; callers that require authentication use the
// strict path in requirePermissionMiddleware instead.
func applySessionFromHeader(c *gin.Context, header string) bool {
	if header == "" {
		return false
	}
	sessionJSON, err := base64.StdEncoding.DecodeString(header)
	if err != nil {
		return false
	}
	var session Session
	if err := json.Unmarshal(sessionJSON, &session); err != nil {
		return false
	}
	c.Set(ContextKeySession, &session)
	c.Set(ContextKeyUserID, session.UserID)
	c.Set(ContextKeyUsername, session.Username)
	c.Set(ContextKeyRoles, session.Roles)
	return true
}

// GetSession is a helper function to get session from gin context
func GetSession(c *gin.Context) (*Session, bool) {
	session, exists := c.Get(ContextKeySession)
	if !exists {
		return nil, false
	}
	s, ok := session.(*Session)
	return s, ok
}

// GetUserID is a helper function to get user ID from gin context
func GetUserID(c *gin.Context) (string, bool) {
	userID, exists := c.Get(ContextKeyUserID)
	if !exists {
		return "", false
	}
	id, ok := userID.(string)
	return id, ok
}

// GetUsername is a helper function to get username from gin context
func GetUsername(c *gin.Context) (string, bool) {
	username, exists := c.Get(ContextKeyUsername)
	if !exists {
		return "", false
	}
	name, ok := username.(string)
	return name, ok
}

// GetRoles is a helper function to get user roles from gin context
func GetRoles(c *gin.Context) ([]string, bool) {
	roles, exists := c.Get(ContextKeyRoles)
	if !exists {
		return nil, false
	}
	r, ok := roles.([]string)
	return r, ok
}

// HasRole checks if the user has a specific role
func HasRole(c *gin.Context, role string) bool {
	roles, ok := GetRoles(c)
	if !ok {
		return false
	}
	for _, r := range roles {
		if r == role {
			return true
		}
	}
	return false
}
