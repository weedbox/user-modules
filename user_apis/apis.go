package user_apis

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/weedbox/queryhelper"
	"go.uber.org/zap"

	"github.com/weedbox/user-modules/auth"
	"github.com/weedbox/user-modules/user"
)

// create creates a user
//
//	@Summary		Create a user
//	@Description	Create a new user account
//	@Tags			User
//	@Accept			json
//	@Produce		json
//	@Param			body	body		CreateRequestBody	true	"User creation payload"
//	@Success		201		{object}	CreateResponse
//	@Failure		400		{object}	ErrorResponse
//	@Failure		409		{object}	ErrorResponse
//	@Failure		500		{object}	ErrorResponse
//	@Security		BearerAuth
//	@Router			/apis/v1/user [post]
func (m *UserAPIs) create(c *gin.Context) {
	var req CreateRequest

	// Bind JSON body
	if err := c.ShouldBindJSON(&req.Body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Build config
	cfg := &user.UserConfig{
		Username:    req.Body.Username,
		Email:       req.Body.Email,
		Password:    req.Body.Password,
		DisplayName: req.Body.DisplayName,
		Roles:       req.Body.Roles,
		Status:      req.Body.Status,
	}

	// Call business layer
	ctx := c.Request.Context()
	u, err := m.Params().User.Create(ctx, cfg)
	if err != nil {
		switch err {
		case user.ErrUsernameExists:
			c.JSON(http.StatusConflict, gin.H{"error": "Username already exists"})
		case user.ErrEmailExists:
			c.JSON(http.StatusConflict, gin.H{"error": "Email already exists"})
		case user.ErrPasswordTooShort:
			c.JSON(http.StatusBadRequest, gin.H{"error": "Password must be at least 8 characters"})
		default:
			m.Logger().Error("Failed to create user", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return
	}

	// Return response
	c.JSON(http.StatusCreated, CreateResponse{
		Message: "user created successfully",
		User:    m.toEntry(u),
	})
}

// get retrieves a user
//
//	@Summary		Get a user
//	@Description	Retrieve a user by ID
//	@Tags			User
//	@Produce		json
//	@Param			id	path		string	true	"User ID"
//	@Success		200	{object}	GetResponse
//	@Failure		400	{object}	ErrorResponse
//	@Failure		404	{object}	ErrorResponse
//	@Failure		500	{object}	ErrorResponse
//	@Security		BearerAuth
//	@Router			/apis/v1/user/{id} [get]
func (m *UserAPIs) get(c *gin.Context) {
	var req GetRequest

	if err := c.ShouldBindUri(&req.URI); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()
	u, err := m.Params().User.Get(ctx, req.URI.ID)
	if err != nil {
		if err == user.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}

		m.Logger().Error("Failed to get user", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, GetResponse{
		User: m.toEntry(u),
	})
}

// update updates a user
//
//	@Summary		Update a user
//	@Description	Update user information by ID
//	@Tags			User
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string				true	"User ID"
//	@Param			body	body		UpdateRequestBody	true	"User update payload"
//	@Success		200		{object}	UpdateResponse
//	@Failure		400		{object}	ErrorResponse
//	@Failure		404		{object}	ErrorResponse
//	@Failure		409		{object}	ErrorResponse
//	@Failure		500		{object}	ErrorResponse
//	@Security		BearerAuth
//	@Router			/apis/v1/user/{id} [put]
func (m *UserAPIs) update(c *gin.Context) {
	var req UpdateRequest

	// Bind URI parameters
	if err := c.ShouldBindUri(&req.URI); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Bind JSON body
	if err := c.ShouldBindJSON(&req.Body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	cfg := &user.UserConfig{
		Username:    req.Body.Username,
		Email:       req.Body.Email,
		DisplayName: req.Body.DisplayName,
		Roles:       req.Body.Roles,
		Status:      req.Body.Status,
	}

	ctx := c.Request.Context()
	u, err := m.Params().User.Update(ctx, req.URI.ID, cfg)
	if err != nil {
		switch err {
		case user.ErrNotFound:
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		case user.ErrUsernameExists:
			c.JSON(http.StatusConflict, gin.H{"error": "Username already exists"})
		case user.ErrEmailExists:
			c.JSON(http.StatusConflict, gin.H{"error": "Email already exists"})
		default:
			m.Logger().Error("Failed to update user", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return
	}

	c.JSON(http.StatusOK, UpdateResponse{
		Message: "user updated successfully",
		User:    m.toEntry(u),
	})
}

// updatePassword resets a user's password (admin operation, no current password required)
//
//	@Summary		Reset user password
//	@Description	Admin reset a user's password (no current password required)
//	@Tags			User
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string						true	"User ID"
//	@Param			body	body		UpdatePasswordRequestBody	true	"New password payload"
//	@Success		200		{object}	UpdatePasswordResponse
//	@Failure		400		{object}	ErrorResponse
//	@Failure		404		{object}	ErrorResponse
//	@Failure		500		{object}	ErrorResponse
//	@Security		BearerAuth
//	@Router			/apis/v1/user/{id}/password [put]
func (m *UserAPIs) updatePassword(c *gin.Context) {
	var req UpdatePasswordRequest

	// Bind URI parameters
	if err := c.ShouldBindUri(&req.URI); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Bind JSON body
	if err := c.ShouldBindJSON(&req.Body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()

	// Update password directly (admin reset)
	if err := m.Params().User.UpdatePassword(ctx, req.URI.ID, req.Body.NewPassword); err != nil {
		switch err {
		case user.ErrNotFound:
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		case user.ErrPasswordTooShort:
			c.JSON(http.StatusBadRequest, gin.H{"error": "Password must be at least 8 characters"})
		default:
			m.Logger().Error("Failed to update password", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return
	}

	c.JSON(http.StatusOK, UpdatePasswordResponse{
		Message: "password reset successfully",
	})
}

// getMe retrieves the authenticated user's own information
//
//	@Summary		Get current user
//	@Description	Retrieve the authenticated user's own information
//	@Tags			Self-Service
//	@Produce		json
//	@Success		200	{object}	GetMeResponse
//	@Failure		401	{object}	ErrorResponse
//	@Failure		404	{object}	ErrorResponse
//	@Failure		500	{object}	ErrorResponse
//	@Security		BearerAuth
//	@Router			/apis/v1/me [get]
func (m *UserAPIs) getMe(c *gin.Context) {
	userID, ok := auth.GetUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	ctx := c.Request.Context()
	u, err := m.Params().User.Get(ctx, userID)
	if err != nil {
		if err == user.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}

		m.Logger().Error("Failed to get user", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, GetMeResponse{
		User: m.toEntry(u),
	})
}

// updateMe updates the authenticated user's own information (cannot change roles/status)
//
//	@Summary		Update current user
//	@Description	Update the authenticated user's own information (cannot change roles/status)
//	@Tags			Self-Service
//	@Accept			json
//	@Produce		json
//	@Param			body	body		UpdateMeRequestBody	true	"Update payload"
//	@Success		200		{object}	UpdateMeResponse
//	@Failure		400		{object}	ErrorResponse
//	@Failure		401		{object}	ErrorResponse
//	@Failure		404		{object}	ErrorResponse
//	@Failure		409		{object}	ErrorResponse
//	@Failure		500		{object}	ErrorResponse
//	@Security		BearerAuth
//	@Router			/apis/v1/me [put]
func (m *UserAPIs) updateMe(c *gin.Context) {
	userID, ok := auth.GetUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	var req UpdateMeRequest
	if err := c.ShouldBindJSON(&req.Body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	cfg := &user.UserConfig{
		Username:    req.Body.Username,
		Email:       req.Body.Email,
		DisplayName: req.Body.DisplayName,
	}

	ctx := c.Request.Context()
	u, err := m.Params().User.Update(ctx, userID, cfg)
	if err != nil {
		switch err {
		case user.ErrNotFound:
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		case user.ErrUsernameExists:
			c.JSON(http.StatusConflict, gin.H{"error": "Username already exists"})
		case user.ErrEmailExists:
			c.JSON(http.StatusConflict, gin.H{"error": "Email already exists"})
		default:
			m.Logger().Error("Failed to update user", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return
	}

	c.JSON(http.StatusOK, UpdateMeResponse{
		Message: "user updated successfully",
		User:    m.toEntry(u),
	})
}

// updateMyPassword updates the authenticated user's own password (requires current password)
//
//	@Summary		Change own password
//	@Description	Update the authenticated user's own password (requires current password)
//	@Tags			Self-Service
//	@Accept			json
//	@Produce		json
//	@Param			body	body		UpdateMyPasswordRequestBody	true	"Password change payload"
//	@Success		200		{object}	UpdateMyPasswordResponse
//	@Failure		400		{object}	ErrorResponse
//	@Failure		401		{object}	ErrorResponse
//	@Failure		404		{object}	ErrorResponse
//	@Failure		500		{object}	ErrorResponse
//	@Security		BearerAuth
//	@Router			/apis/v1/me/password [put]
func (m *UserAPIs) updateMyPassword(c *gin.Context) {
	userID, ok := auth.GetUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	var req UpdateMyPasswordRequest
	if err := c.ShouldBindJSON(&req.Body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()

	// Verify current password first
	if err := m.Params().User.VerifyPassword(ctx, userID, req.Body.CurrentPassword); err != nil {
		switch err {
		case user.ErrNotFound:
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		case user.ErrInvalidPassword:
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Current password is incorrect"})
		default:
			m.Logger().Error("Failed to verify password", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return
	}

	// Update password
	if err := m.Params().User.UpdatePassword(ctx, userID, req.Body.NewPassword); err != nil {
		switch err {
		case user.ErrNotFound:
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		case user.ErrPasswordTooShort:
			c.JSON(http.StatusBadRequest, gin.H{"error": "Password must be at least 8 characters"})
		default:
			m.Logger().Error("Failed to update password", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return
	}

	c.JSON(http.StatusOK, UpdateMyPasswordResponse{
		Message: "password updated successfully",
	})
}

// delete deletes a user
//
//	@Summary		Delete a user
//	@Description	Delete a user by ID
//	@Tags			User
//	@Produce		json
//	@Param			id	path		string	true	"User ID"
//	@Success		200	{object}	DeleteResponse
//	@Failure		400	{object}	ErrorResponse
//	@Failure		404	{object}	ErrorResponse
//	@Failure		500	{object}	ErrorResponse
//	@Security		BearerAuth
//	@Router			/apis/v1/user/{id} [delete]
func (m *UserAPIs) delete(c *gin.Context) {
	var req DeleteRequest

	if err := c.ShouldBindUri(&req.URI); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()
	err := m.Params().User.Delete(ctx, req.URI.ID)
	if err != nil {
		if err == user.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}

		m.Logger().Error("Failed to delete user", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, DeleteResponse{
		Message: "user deleted successfully",
	})
}

// list lists users with pagination
//
//	@Summary		List users
//	@Description	List users with pagination, search, and filtering
//	@Tags			User
//	@Produce		json
//	@Param			page			query		int		false	"Page number"				default(1)
//	@Param			page_size		query		int		false	"Page size"					default(10)
//	@Param			keywords		query		string	false	"Search keywords"
//	@Param			search_fields	query		string	false	"Comma-separated search fields"
//	@Param			orderby			query		string	false	"Comma-separated order-by fields"
//	@Param			order			query		int		false	"Sort order: 1=asc, -1=desc"	default(-1)
//	@Param			status			query		string	false	"Filter by status"
//	@Param			role			query		string	false	"Filter by role"
//	@Success		200				{object}	ListResponse
//	@Failure		400				{object}	ErrorResponse
//	@Failure		500				{object}	ErrorResponse
//	@Security		BearerAuth
//	@Router			/apis/v1/users [get]
func (m *UserAPIs) list(c *gin.Context) {
	var req ListRequest

	// Bind query parameters
	if err := c.ShouldBindQuery(&req.Query); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Set defaults
	if req.Query.Page == 0 {
		req.Query.Page = 1
	}
	if req.Query.PageSize == 0 {
		req.Query.PageSize = 10
	}
	if req.Query.Order == 0 {
		req.Query.Order = -1 // Default to descending (newest first)
	}

	// Parse comma-separated fields
	searchFields := parseCommaSeparated(req.Query.SearchFields)
	orderBy := parseCommaSeparated(req.Query.OrderBy)

	// Build filter conditions
	filters := make([]queryhelper.FilterCondition, 0)
	if req.Query.Status != "" {
		filters = append(filters, queryhelper.FilterCondition{
			Field:    "status",
			Operator: "=",
			Value:    req.Query.Status,
		})
	}
	if req.Query.Role != "" {
		filters = append(filters, queryhelper.FilterCondition{
			Field:    "role",
			Operator: "=",
			Value:    req.Query.Role,
		})
	}

	// Build QueryHelper
	qh := queryhelper.NewQueryHelper(
		queryhelper.WithPage(req.Query.Page),
		queryhelper.WithPageSize(req.Query.PageSize),
		queryhelper.WithSearchText(req.Query.Keywords),
		queryhelper.WithSearchFields(searchFields),
		queryhelper.WithOrderBy(orderBy),
		queryhelper.WithSortFactor(req.Query.Order),
		queryhelper.WithFilters(filters),
	)

	// Build query conditions
	listReq := &user.ListUsersRequest{}
	if req.Query.Status != "" {
		listReq.Status = &req.Query.Status
	}
	if req.Query.Role != "" {
		listReq.Role = &req.Query.Role
	}

	// Call business layer
	ctx := c.Request.Context()
	result, err := m.Params().User.List(ctx, listReq, qh)
	if err != nil {
		m.Logger().Error("Failed to list users", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Transform to response format
	entries := make([]*UserEntry, len(result.Data))
	for i, u := range result.Data {
		entries[i] = m.toEntry(u)
	}

	// Get query info
	qi := result.QueryHelper.Info()

	c.JSON(http.StatusOK, ListResponse{
		Total:      qi.Pagination.Total,
		Page:       qi.Pagination.Page,
		PageSize:   qi.Pagination.PageSize,
		TotalPages: qi.Pagination.TotalPages,
		OrderBy:    qi.Conditions.OrderBy,
		Order:      qi.Conditions.SortFactor,
		Keywords:   qi.Conditions.SearchText,
		Users:      entries,
	})
}

// authenticate authenticates a user
//
//	@Summary		Authenticate a user
//	@Description	Verify user credentials (username/email and password)
//	@Tags			User
//	@Accept			json
//	@Produce		json
//	@Param			body	body		AuthenticateRequestBody	true	"Credentials payload"
//	@Success		200		{object}	AuthenticateResponse
//	@Failure		400		{object}	ErrorResponse
//	@Failure		401		{object}	ErrorResponse
//	@Failure		500		{object}	ErrorResponse
//	@Security		BearerAuth
//	@Router			/apis/v1/user/authenticate [post]
func (m *UserAPIs) authenticate(c *gin.Context) {
	var req AuthenticateRequest

	if err := c.ShouldBindJSON(&req.Body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()
	u, err := m.Params().User.Authenticate(ctx, req.Body.Identifier, req.Body.Password)
	if err != nil {
		if err == user.ErrInvalidCredentials {
			c.JSON(http.StatusUnauthorized, AuthenticateResponse{
				Success: false,
				Message: "Invalid credentials",
			})
			return
		}

		m.Logger().Error("Failed to authenticate user", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, AuthenticateResponse{
		Success: true,
		Message: "Authentication successful",
		User:    m.toEntry(u),
	})
}

// toEntry converts business layer structure to API response structure
func (m *UserAPIs) toEntry(u *user.User) *UserEntry {
	entry := &UserEntry{
		ID:          u.ID,
		Username:    u.Username,
		Email:       u.Email,
		DisplayName: u.DisplayName,
		Roles:       u.Roles,
		Status:      u.Status,
		CreatedAt:   u.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:   u.UpdatedAt.UTC().Format(time.RFC3339),
	}

	if u.LastLoginAt != nil {
		lastLogin := u.LastLoginAt.UTC().Format(time.RFC3339)
		entry.LastLoginAt = &lastLogin
	}

	return entry
}

// parseCommaSeparated parses comma-separated string
func parseCommaSeparated(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}
