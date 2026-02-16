package rbac

import (
	"context"

	"github.com/spf13/viper"
	"github.com/weedbox/common-modules/database"
	"github.com/weedbox/privy"
	"github.com/weedbox/weedbox"
	"go.uber.org/fx"
	"go.uber.org/zap"

	"github.com/weedbox/user-modules/permissions"
)

const ModuleName = "RBAC"

type options struct {
	resourceConfigs []privy.ResourceConfig
	defaultRoles    map[string]privy.RoleConfig
}

// Option is a function that configures the RBAC module
type Option func(*options)

// WithResourceConfigs sets extra resource configurations to merge with builtins
func WithResourceConfigs(configs []privy.ResourceConfig) Option {
	return func(o *options) {
		o.resourceConfigs = configs
	}
}

// WithDefaultRoles sets extra default roles to merge with builtins
func WithDefaultRoles(roles map[string]privy.RoleConfig) Option {
	return func(o *options) {
		o.defaultRoles = roles
	}
}

type Params struct {
	weedbox.Params
	Database database.DatabaseConnector
}

type RBACManager struct {
	weedbox.Module[*Params]
	manager *privy.Manager
	storage privy.Storage
	opts    *options
}

func Module(scope string, opts ...Option) fx.Option {
	m := new(RBACManager)
	m.opts = &options{}
	for _, opt := range opts {
		opt(m.opts)
	}

	return fx.Module(
		scope,
		fx.Supply(fx.Annotated{Name: scope, Target: m}),
		fx.Invoke(func(p Params) {
			weedbox.InitModule(scope, &p, m)
		}),
	)
}

func (m *RBACManager) InitDefaultConfigs() {
	// Whether to initialize default roles on startup
	viper.SetDefault(m.GetConfigPath("init_default_roles"), true)
}

func (m *RBACManager) OnStart(ctx context.Context) error {
	m.Logger().Info("Starting " + ModuleName)

	// Initialize GORM storage
	db := m.Params().Database.GetDB()
	storage := privy.NewGormStorage(db)

	// Initialize storage (create tables)
	if err := storage.Initialize(); err != nil {
		m.Logger().Error("Failed to initialize RBAC storage", zap.Error(err))
		return err
	}

	// Store storage reference for direct operations
	m.storage = storage

	// Create manager with storage
	m.manager = privy.CreateManager(privy.WithStorage(storage))

	// Initialize resources
	if err := m.initResources(); err != nil {
		m.Logger().Error("Failed to initialize resources", zap.Error(err))
		return err
	}

	// Initialize default roles if enabled
	if viper.GetBool(m.GetConfigPath("init_default_roles")) {
		if err := m.initDefaultRoles(); err != nil {
			m.Logger().Error("Failed to initialize default roles", zap.Error(err))
			return err
		}
	}

	m.Logger().Info("Started " + ModuleName)
	return nil
}

func (m *RBACManager) OnStop(ctx context.Context) error {
	m.Logger().Info("Stopped " + ModuleName)
	return nil
}

// initResources initializes all resource definitions
func (m *RBACManager) initResources() error {
	// Merge builtin resources with user-provided extra resources
	var configs []privy.ResourceConfig
	if m.opts != nil && len(m.opts.resourceConfigs) > 0 {
		configs = permissions.MergeResourceConfigs(m.opts.resourceConfigs)
	} else {
		configs = permissions.GetBuiltinResourceConfigs()
	}

	for _, config := range configs {
		// Check if resource already exists
		_, err := m.manager.GetResource(config.Key)
		if err == nil {
			// Resource exists, skip
			m.Logger().Debug("Resource already exists, skipping", zap.String("key", config.Key))
			continue
		}

		// Create resource
		_, err = m.manager.CreateResource(config)
		if err != nil && err != privy.ErrResourceExists {
			return err
		}

		m.Logger().Info("Created resource", zap.String("key", config.Key))
	}

	return nil
}

// initDefaultRoles initializes default role definitions
func (m *RBACManager) initDefaultRoles() error {
	// Merge builtin roles with user-provided extra roles
	var roles map[string]privy.RoleConfig
	if m.opts != nil && len(m.opts.defaultRoles) > 0 {
		roles = permissions.MergeDefaultRoles(m.opts.defaultRoles)
	} else {
		roles = permissions.GetBuiltinDefaultRoles()
	}

	for key, config := range roles {
		// Check if role already exists
		_, err := m.manager.GetRole(key)
		if err == nil {
			// Role exists, skip
			m.Logger().Debug("Role already exists, skipping", zap.String("key", key))
			continue
		}

		// Create role
		_, err = m.manager.CreateRole(key, config)
		if err != nil && err != privy.ErrRoleExists {
			return err
		}

		m.Logger().Info("Created role", zap.String("key", key))
	}

	return nil
}

// GetManager returns the privy manager
func (m *RBACManager) GetManager() *privy.Manager {
	return m.manager
}

// CheckPermission checks if a role has the required permission
func (m *RBACManager) CheckPermission(roleKey, permission string) (bool, error) {
	return m.manager.CheckRolePermission(roleKey, permission)
}

// CheckPermissions checks if any of the given roles has the required permission
func (m *RBACManager) CheckPermissions(roleKeys []string, permission string) (bool, error) {
	return m.manager.CheckRolesPermission(roleKeys, permission)
}

// CreateRole creates a new role
func (m *RBACManager) CreateRole(key string, config privy.RoleConfig) (*privy.Role, error) {
	return m.manager.CreateRole(key, config)
}

// GetRole gets a role by key
func (m *RBACManager) GetRole(key string) (*privy.Role, error) {
	return m.manager.GetRole(key)
}

// ListRoles lists all roles
func (m *RBACManager) ListRoles() ([]privy.Role, error) {
	return m.manager.ListRoles()
}

// DeleteRole deletes a role
func (m *RBACManager) DeleteRole(key string) error {
	return m.manager.DeleteRole(key)
}

// AssignPermissions adds permissions to a role
func (m *RBACManager) AssignPermissions(roleKey string, permissions []string) error {
	return m.manager.AssignPermissions(roleKey, permissions)
}

// RemovePermissions removes permissions from a role
func (m *RBACManager) RemovePermissions(roleKey string, permissions []string) error {
	return m.manager.RemovePermissions(roleKey, permissions)
}

// UpdateRole updates an existing role's name, description, and permissions
func (m *RBACManager) UpdateRole(key string, config privy.RoleConfig) (*privy.Role, error) {
	role, err := m.manager.GetRole(key)
	if err != nil {
		return nil, err
	}

	role.Name = config.Name
	role.Description = config.Description
	role.Permissions = config.Permissions

	if err := m.storage.UpdateRole(role); err != nil {
		return nil, err
	}

	return role, nil
}

// GetResource gets a resource by path
func (m *RBACManager) GetResource(path string) (*privy.Resource, error) {
	return m.manager.GetResource(path)
}

// ListResources lists all top-level resources
func (m *RBACManager) ListResources() ([]privy.Resource, error) {
	return m.manager.ListResources()
}
