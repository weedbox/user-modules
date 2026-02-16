package role_apis

// ========== Request Structures ==========

// --- Create ---

type CreateRequestBody struct {
	Key         string   `json:"key" binding:"required,min=2,max=255"`
	Name        string   `json:"name" binding:"required,min=1,max=255"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
}

type CreateRequest struct {
	Body CreateRequestBody
}

// --- Get ---

type GetRequestURI struct {
	Key string `uri:"key" binding:"required"`
}

type GetRequest struct {
	URI GetRequestURI
}

// --- Update ---

type UpdateRequestURI struct {
	Key string `uri:"key" binding:"required"`
}

type UpdateRequestBody struct {
	Name        string   `json:"name" binding:"required,min=1,max=255"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
}

type UpdateRequest struct {
	URI  UpdateRequestURI
	Body UpdateRequestBody
}

// --- Delete ---

type DeleteRequestURI struct {
	Key string `uri:"key" binding:"required"`
}

type DeleteRequest struct {
	URI DeleteRequestURI
}

// --- Assign/Remove Permissions ---

type PermissionsRequestURI struct {
	Key string `uri:"key" binding:"required"`
}

type PermissionsRequestBody struct {
	Permissions []string `json:"permissions" binding:"required,min=1"`
}

type PermissionsRequest struct {
	URI  PermissionsRequestURI
	Body PermissionsRequestBody
}

// --- Get Resource ---

type GetResourceRequestURI struct {
	Path string `uri:"path" binding:"required"`
}

type GetResourceRequest struct {
	URI GetResourceRequestURI
}

// ========== Response Structures ==========

// RoleEntry role item in API response
type RoleEntry struct {
	ID          uint     `json:"id"`
	Key         string   `json:"key"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
	CreatedAt   string   `json:"created_at"`
	UpdatedAt   string   `json:"updated_at"`
}

// ActionEntry action item in API response
type ActionEntry struct {
	Key         string `json:"key"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// ResourceEntry resource item in API response
type ResourceEntry struct {
	Key          string          `json:"key"`
	Name         string          `json:"name"`
	Description  string          `json:"description"`
	Actions      []ActionEntry   `json:"actions"`
	SubResources []ResourceEntry `json:"sub_resources,omitempty"`
}

// CreateResponse create response
type CreateResponse struct {
	Message string     `json:"message"`
	Role    *RoleEntry `json:"role"`
}

// GetResponse get response
type GetResponse struct {
	Role *RoleEntry `json:"role"`
}

// UpdateResponse update response
type UpdateResponse struct {
	Message string     `json:"message"`
	Role    *RoleEntry `json:"role"`
}

// DeleteResponse delete response
type DeleteResponse struct {
	Message string `json:"message"`
}

// ListResponse list response
type ListResponse struct {
	Roles []*RoleEntry `json:"roles"`
}

// AssignPermissionsResponse assign permissions response
type AssignPermissionsResponse struct {
	Message string     `json:"message"`
	Role    *RoleEntry `json:"role"`
}

// RemovePermissionsResponse remove permissions response
type RemovePermissionsResponse struct {
	Message string     `json:"message"`
	Role    *RoleEntry `json:"role"`
}

// ListResourcesResponse list resources response
type ListResourcesResponse struct {
	Resources []ResourceEntry `json:"resources"`
}

// GetResourceResponse get resource response
type GetResourceResponse struct {
	Resource *ResourceEntry `json:"resource"`
}
