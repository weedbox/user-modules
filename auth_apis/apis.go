package auth_apis

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/weedbox/user-modules/auth"
)

// login authenticates a user and returns tokens
func (m *AuthAPIs) login(c *gin.Context) {
	var req LoginRequest

	if err := c.ShouldBindJSON(&req.Body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()
	tokenPair, err := m.Params().Auth.Login(ctx, req.Body.Identifier, req.Body.Password)
	if err != nil {
		switch err {
		case auth.ErrInvalidCredentials:
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		case auth.ErrUserInactive:
			c.JSON(http.StatusForbidden, gin.H{"error": "User account is not active"})
		default:
			m.Logger().Error("Failed to login", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Login failed"})
		}
		return
	}

	// Get user claims from the access token to return user info
	claims, _ := m.Params().Auth.ValidateAccessToken(tokenPair.AccessToken)

	var userInfo *UserInfo
	if claims != nil {
		userInfo = &UserInfo{
			ID:          claims.UserID,
			Username:    claims.Username,
			Email:       claims.Email,
			DisplayName: claims.DisplayName,
			Roles:       claims.Roles,
		}
	}

	c.JSON(http.StatusOK, LoginResponse{
		Message: "Login successful",
		Token: TokenResponse{
			AccessToken:      tokenPair.AccessToken,
			RefreshToken:     tokenPair.RefreshToken,
			TokenType:        tokenPair.TokenType,
			ExpiresIn:        tokenPair.ExpiresIn,
			ExpiresAt:        tokenPair.ExpiresAt,
			RefreshExpiresAt: tokenPair.RefreshExpiresAt,
		},
		User: userInfo,
	})
}

// refresh exchanges a refresh token for new tokens
func (m *AuthAPIs) refresh(c *gin.Context) {
	var req RefreshRequest

	if err := c.ShouldBindJSON(&req.Body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()
	tokenPair, err := m.Params().Auth.RefreshTokens(ctx, req.Body.RefreshToken)
	if err != nil {
		switch err {
		case auth.ErrTokenNotFound:
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
		case auth.ErrTokenExpired:
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Refresh token has expired"})
		case auth.ErrTokenRevoked:
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Refresh token has been revoked"})
		case auth.ErrUserInactive:
			c.JSON(http.StatusForbidden, gin.H{"error": "User account is not active"})
		default:
			m.Logger().Error("Failed to refresh tokens", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Token refresh failed"})
		}
		return
	}

	c.JSON(http.StatusOK, RefreshResponse{
		Message: "Token refreshed successfully",
		Token: TokenResponse{
			AccessToken:      tokenPair.AccessToken,
			RefreshToken:     tokenPair.RefreshToken,
			TokenType:        tokenPair.TokenType,
			ExpiresIn:        tokenPair.ExpiresIn,
			ExpiresAt:        tokenPair.ExpiresAt,
			RefreshExpiresAt: tokenPair.RefreshExpiresAt,
		},
	})
}

// logout revokes a refresh token
func (m *AuthAPIs) logout(c *gin.Context) {
	var req LogoutRequest

	if err := c.ShouldBindJSON(&req.Body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()
	err := m.Params().Auth.Logout(ctx, req.Body.RefreshToken)
	if err != nil {
		switch err {
		case auth.ErrTokenNotFound:
			c.JSON(http.StatusNotFound, gin.H{"error": "Refresh token not found"})
		default:
			m.Logger().Error("Failed to logout", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Logout failed"})
		}
		return
	}

	c.JSON(http.StatusOK, LogoutResponse{
		Message: "Logged out successfully",
	})
}
