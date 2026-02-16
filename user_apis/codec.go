package user_apis

// ========== Request Structures ==========

// --- Create ---

type CreateRequestBody struct {
	Username    string   `json:"username" binding:"required,min=3,max=255"`
	Email       string   `json:"email" binding:"required,email"`
	Password    string   `json:"password" binding:"required,min=8"`
	DisplayName string   `json:"display_name"`
	Roles       []string `json:"roles"` // Multiple roles
	Status      string   `json:"status" binding:"omitempty,oneof=active inactive suspended"`
}

type CreateRequest struct {
	Body CreateRequestBody
}

// --- Get ---

type GetRequestURI struct {
	ID string `uri:"id" binding:"required"`
}

type GetRequest struct {
	URI GetRequestURI
}

// --- Update ---

type UpdateRequestURI struct {
	ID string `uri:"id" binding:"required"`
}

type UpdateRequestBody struct {
	Username    string   `json:"username" binding:"omitempty,min=3,max=255"`
	Email       string   `json:"email" binding:"omitempty,email"`
	DisplayName string   `json:"display_name"`
	Roles       []string `json:"roles"` // Multiple roles
	Status      string   `json:"status" binding:"omitempty,oneof=active inactive suspended"`
}

type UpdateRequest struct {
	URI  UpdateRequestURI
	Body UpdateRequestBody
}

// --- Update Password ---

type UpdatePasswordRequestURI struct {
	ID string `uri:"id" binding:"required"`
}

type UpdatePasswordRequestBody struct {
	CurrentPassword string `json:"current_password" binding:"required"`
	NewPassword     string `json:"new_password" binding:"required,min=8"`
}

type UpdatePasswordRequest struct {
	URI  UpdatePasswordRequestURI
	Body UpdatePasswordRequestBody
}

// --- Delete ---

type DeleteRequestURI struct {
	ID string `uri:"id" binding:"required"`
}

type DeleteRequest struct {
	URI DeleteRequestURI
}

// --- List ---

type ListRequestQuery struct {
	Page         int    `form:"page"`
	PageSize     int    `form:"page_size"`
	Keywords     string `form:"keywords"`
	SearchFields string `form:"search_fields"`
	OrderBy      string `form:"orderby"`
	Order        int    `form:"order"`
	Status       string `form:"status"`
	Role         string `form:"role"`
}

type ListRequest struct {
	Query ListRequestQuery
}

// --- Authenticate ---

type AuthenticateRequestBody struct {
	Identifier string `json:"identifier" binding:"required"` // username or email
	Password   string `json:"password" binding:"required"`
}

type AuthenticateRequest struct {
	Body AuthenticateRequestBody
}

// ========== Response Structures ==========

// UserEntry user item in API response
type UserEntry struct {
	ID          string   `json:"id"`
	Username    string   `json:"username"`
	Email       string   `json:"email"`
	DisplayName string   `json:"display_name"`
	Roles       []string `json:"roles"`
	Status      string   `json:"status"`
	LastLoginAt *string  `json:"last_login_at,omitempty"`
	CreatedAt   string   `json:"created_at"`
	UpdatedAt   string   `json:"updated_at"`
}

// CreateResponse create response
type CreateResponse struct {
	Message string     `json:"message"`
	User    *UserEntry `json:"user"`
}

// GetResponse get response
type GetResponse struct {
	User *UserEntry `json:"user"`
}

// UpdateResponse update response
type UpdateResponse struct {
	Message string     `json:"message"`
	User    *UserEntry `json:"user"`
}

// UpdatePasswordResponse update password response
type UpdatePasswordResponse struct {
	Message string `json:"message"`
}

// DeleteResponse delete response
type DeleteResponse struct {
	Message string `json:"message"`
}

// ListResponse list response
type ListResponse struct {
	Total      int64        `json:"total"`
	Page       int          `json:"page"`
	PageSize   int          `json:"page_size"`
	TotalPages int          `json:"total_pages"`
	OrderBy    []string     `json:"order_by"`
	Order      int          `json:"order"`
	Keywords   string       `json:"keywords,omitempty"`
	Users      []*UserEntry `json:"users"`
}

// AuthenticateResponse authenticate response
type AuthenticateResponse struct {
	Success bool       `json:"success"`
	Message string     `json:"message"`
	User    *UserEntry `json:"user,omitempty"`
}
