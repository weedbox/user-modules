package role_apis

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/weedbox/privy"
	"go.uber.org/zap"
)

// create creates a new role
func (m *RoleAPIs) create(c *gin.Context) {
	var req CreateRequest

	if err := c.ShouldBindJSON(&req.Body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	config := privy.RoleConfig{
		Name:        req.Body.Name,
		Description: req.Body.Description,
		Permissions: req.Body.Permissions,
	}

	role, err := m.Params().RBAC.CreateRole(req.Body.Key, config)
	if err != nil {
		if err == privy.ErrRoleExists {
			c.JSON(http.StatusConflict, gin.H{"error": "Role already exists"})
			return
		}

		m.Logger().Error("Failed to create role", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, CreateResponse{
		Message: "role created successfully",
		Role:    m.toRoleEntry(role),
	})
}

// get retrieves a role by key
func (m *RoleAPIs) get(c *gin.Context) {
	var req GetRequest

	if err := c.ShouldBindUri(&req.URI); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	role, err := m.Params().RBAC.GetRole(req.URI.Key)
	if err != nil {
		if err == privy.ErrRoleNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Role not found"})
			return
		}

		m.Logger().Error("Failed to get role", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, GetResponse{
		Role: m.toRoleEntry(role),
	})
}

// update updates an existing role
func (m *RoleAPIs) update(c *gin.Context) {
	var req UpdateRequest

	if err := c.ShouldBindUri(&req.URI); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := c.ShouldBindJSON(&req.Body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	config := privy.RoleConfig{
		Name:        req.Body.Name,
		Description: req.Body.Description,
		Permissions: req.Body.Permissions,
	}

	role, err := m.Params().RBAC.UpdateRole(req.URI.Key, config)
	if err != nil {
		if err == privy.ErrRoleNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Role not found"})
			return
		}

		m.Logger().Error("Failed to update role", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, UpdateResponse{
		Message: "role updated successfully",
		Role:    m.toRoleEntry(role),
	})
}

// delete deletes a role by key
func (m *RoleAPIs) delete(c *gin.Context) {
	var req DeleteRequest

	if err := c.ShouldBindUri(&req.URI); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err := m.Params().RBAC.DeleteRole(req.URI.Key)
	if err != nil {
		if err == privy.ErrRoleNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Role not found"})
			return
		}

		m.Logger().Error("Failed to delete role", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, DeleteResponse{
		Message: "role deleted successfully",
	})
}

// list lists all roles
func (m *RoleAPIs) list(c *gin.Context) {
	roles, err := m.Params().RBAC.ListRoles()
	if err != nil {
		m.Logger().Error("Failed to list roles", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	entries := make([]*RoleEntry, len(roles))
	for i := range roles {
		entries[i] = m.toRoleEntry(&roles[i])
	}

	c.JSON(http.StatusOK, ListResponse{
		Roles: entries,
	})
}

// assignPermissions adds permissions to a role
func (m *RoleAPIs) assignPermissions(c *gin.Context) {
	var req PermissionsRequest

	if err := c.ShouldBindUri(&req.URI); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := c.ShouldBindJSON(&req.Body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err := m.Params().RBAC.AssignPermissions(req.URI.Key, req.Body.Permissions)
	if err != nil {
		if err == privy.ErrRoleNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Role not found"})
			return
		}

		m.Logger().Error("Failed to assign permissions", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Fetch updated role to return
	role, err := m.Params().RBAC.GetRole(req.URI.Key)
	if err != nil {
		m.Logger().Error("Failed to get role after assign", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, AssignPermissionsResponse{
		Message: "permissions assigned successfully",
		Role:    m.toRoleEntry(role),
	})
}

// removePermissions removes permissions from a role
func (m *RoleAPIs) removePermissions(c *gin.Context) {
	var req PermissionsRequest

	if err := c.ShouldBindUri(&req.URI); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := c.ShouldBindJSON(&req.Body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err := m.Params().RBAC.RemovePermissions(req.URI.Key, req.Body.Permissions)
	if err != nil {
		if err == privy.ErrRoleNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Role not found"})
			return
		}

		m.Logger().Error("Failed to remove permissions", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Fetch updated role to return
	role, err := m.Params().RBAC.GetRole(req.URI.Key)
	if err != nil {
		m.Logger().Error("Failed to get role after remove", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, RemovePermissionsResponse{
		Message: "permissions removed successfully",
		Role:    m.toRoleEntry(role),
	})
}

// listResources lists all top-level resources
func (m *RoleAPIs) listResources(c *gin.Context) {
	resources, err := m.Params().RBAC.ListResources()
	if err != nil {
		m.Logger().Error("Failed to list resources", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	entries := make([]ResourceEntry, len(resources))
	for i := range resources {
		entries[i] = m.toResourceEntry(&resources[i])
	}

	c.JSON(http.StatusOK, ListResourcesResponse{
		Resources: entries,
	})
}

// getResource gets a resource by path
func (m *RoleAPIs) getResource(c *gin.Context) {
	// Gin wildcard includes leading slash, trim it
	path := strings.TrimPrefix(c.Param("path"), "/")
	if path == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "resource path is required"})
		return
	}

	resource, err := m.Params().RBAC.GetResource(path)
	if err != nil {
		if err == privy.ErrResourceNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Resource not found"})
			return
		}

		m.Logger().Error("Failed to get resource", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	entry := m.toResourceEntry(resource)
	c.JSON(http.StatusOK, GetResourceResponse{
		Resource: &entry,
	})
}

// toRoleEntry converts a privy.Role to API response entry
func (m *RoleAPIs) toRoleEntry(role *privy.Role) *RoleEntry {
	perms := role.Permissions
	if perms == nil {
		perms = []string{}
	}

	return &RoleEntry{
		ID:          role.ID,
		Key:         role.Key,
		Name:        role.Name,
		Description: role.Description,
		Permissions: perms,
		CreatedAt:   role.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:   role.UpdatedAt.UTC().Format(time.RFC3339),
	}
}

// toResourceEntry converts a privy.Resource to API response entry
func (m *RoleAPIs) toResourceEntry(resource *privy.Resource) ResourceEntry {
	actions := make([]ActionEntry, len(resource.Actions))
	for i, a := range resource.Actions {
		actions[i] = ActionEntry{
			Key:         a.Key,
			Name:        a.Name,
			Description: a.Description,
		}
	}

	var subResources []ResourceEntry
	if len(resource.SubResources) > 0 {
		subResources = make([]ResourceEntry, len(resource.SubResources))
		for i := range resource.SubResources {
			subResources[i] = m.toResourceEntry(&resource.SubResources[i])
		}
	}

	return ResourceEntry{
		Key:          resource.Key,
		Name:         resource.Name,
		Description:  resource.Description,
		Actions:      actions,
		SubResources: subResources,
	}
}
