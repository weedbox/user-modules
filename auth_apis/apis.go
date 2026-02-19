package auth_apis

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/weedbox/user-modules/auth"
)

// login authenticates a user and returns tokens
//
//	@Summary		Login
//	@Description	Authenticate with username/email and password to obtain tokens
//	@Tags			Authentication
//	@Accept			json
//	@Produce		json
//	@Param			body	body		LoginRequestBody	true	"Login credentials"
//	@Success		200		{object}	LoginResponse
//	@Failure		400		{object}	ErrorResponse
//	@Failure		401		{object}	ErrorResponse
//	@Failure		403		{object}	ErrorResponse
//	@Failure		500		{object}	ErrorResponse
//	@Router			/apis/v1/auth/login [post]
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
//
//	@Summary		Refresh tokens
//	@Description	Exchange a refresh token for a new token pair
//	@Tags			Authentication
//	@Accept			json
//	@Produce		json
//	@Param			body	body		RefreshRequestBody	true	"Refresh token"
//	@Success		200		{object}	RefreshResponse
//	@Failure		400		{object}	ErrorResponse
//	@Failure		401		{object}	ErrorResponse
//	@Failure		403		{object}	ErrorResponse
//	@Failure		500		{object}	ErrorResponse
//	@Router			/apis/v1/auth/refresh [post]
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
//
//	@Summary		Logout
//	@Description	Revoke a refresh token
//	@Tags			Authentication
//	@Accept			json
//	@Produce		json
//	@Param			body	body		LogoutRequestBody	true	"Refresh token to revoke"
//	@Success		200		{object}	LogoutResponse
//	@Failure		400		{object}	ErrorResponse
//	@Failure		404		{object}	ErrorResponse
//	@Failure		500		{object}	ErrorResponse
//	@Router			/apis/v1/auth/logout [post]
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
