package role_apis

import (
	"context"

	"github.com/gin-gonic/gin"
	"github.com/weedbox/common-modules/http_server"
	"github.com/weedbox/weedbox"
	"go.uber.org/fx"

	"github.com/weedbox/user-modules/auth"
	"github.com/weedbox/user-modules/permissions"
	"github.com/weedbox/user-modules/rbac"
)

const ModuleName = "RoleAPIs"

type Params struct {
	weedbox.Params
	HTTPServer *http_server.HTTPServer
	RBAC       *rbac.RBACManager `name:"rbac"`
	Auth       *auth.AuthManager `name:"auth"`
}

// requirePerm is a helper to get the require_permission middleware
func (m *RoleAPIs) requirePerm(permission string) gin.HandlerFunc {
	return m.Params().Auth.GetMiddleware("require_permission").(func(string) gin.HandlerFunc)(permission)
}

type RoleAPIs struct {
	weedbox.Module[*Params]
}

func Module(scope string) fx.Option {
	m := new(RoleAPIs)

	return fx.Module(
		scope,
		fx.Supply(fx.Annotated{Name: scope, Target: m}),
		fx.Invoke(func(p Params) {
			weedbox.InitModule(scope, &p, m)
		}),
	)
}

func (m *RoleAPIs) InitDefaultConfigs() {
	// API-specific configs if needed
}

func (m *RoleAPIs) OnStart(ctx context.Context) error {
	m.Logger().Info("Starting " + ModuleName)

	// Register routes
	router := m.Params().HTTPServer.GetRouter().Group("/apis/v1")

	// List (plural form)
	router.GET("/roles", m.requirePerm(permissions.PermRoleList), m.list)

	// CRUD (singular form)
	router.POST("/role", m.requirePerm(permissions.PermRoleCreate), m.create)
	router.GET("/role/:key", m.requirePerm(permissions.PermRoleRead), m.get)
	router.PUT("/role/:key", m.requirePerm(permissions.PermRoleUpdate), m.update)
	router.DELETE("/role/:key", m.requirePerm(permissions.PermRoleDelete), m.delete)

	// Permission management
	router.POST("/role/:key/permissions", m.requirePerm(permissions.PermRoleUpdate), m.assignPermissions)
	router.DELETE("/role/:key/permissions", m.requirePerm(permissions.PermRoleUpdate), m.removePermissions)

	// Resource browsing
	router.GET("/resources", m.requirePerm(permissions.PermRoleRead), m.listResources)
	router.GET("/resource/*path", m.requirePerm(permissions.PermRoleRead), m.getResource)

	m.Logger().Info("Started " + ModuleName)
	return nil
}

func (m *RoleAPIs) OnStop(ctx context.Context) error {
	m.Logger().Info("Stopped " + ModuleName)
	return nil
}
