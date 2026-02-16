package user_apis

import (
	"context"

	"github.com/gin-gonic/gin"
	"github.com/weedbox/common-modules/http_server"
	"github.com/weedbox/weedbox"
	"go.uber.org/fx"

	"github.com/weedbox/user-modules/auth"
	"github.com/weedbox/user-modules/permissions"
	"github.com/weedbox/user-modules/user"
)

const ModuleName = "UserAPIs"

type Params struct {
	weedbox.Params
	HTTPServer *http_server.HTTPServer
	User       *user.UserManager `name:"user"`
	Auth       *auth.AuthManager `name:"auth"`
}

// requirePerm is a helper to get the require_permission middleware
func (m *UserAPIs) requirePerm(permission string) gin.HandlerFunc {
	return m.Params().Auth.GetMiddleware("require_permission").(func(string) gin.HandlerFunc)(permission)
}

type UserAPIs struct {
	weedbox.Module[*Params]
}

func Module(scope string) fx.Option {
	m := new(UserAPIs)

	return fx.Module(
		scope,
		fx.Supply(fx.Annotated{Name: scope, Target: m}),
		fx.Invoke(func(p Params) {
			weedbox.InitModule(scope, &p, m)
		}),
	)
}

func (m *UserAPIs) InitDefaultConfigs() {
	// API-specific configs if needed
}

func (m *UserAPIs) OnStart(ctx context.Context) error {
	m.Logger().Info("Starting " + ModuleName)

	// Register routes
	router := m.Params().HTTPServer.GetRouter().Group("/apis/v1")

	// List (plural form)
	router.GET("/users", m.requirePerm(permissions.PermUserList), m.list)

	// CRUD (singular form)
	router.POST("/user", m.requirePerm(permissions.PermUserCreate), m.create)
	router.GET("/user/:id", m.requirePerm(permissions.PermUserRead), m.get)
	router.PUT("/user/:id", m.requirePerm(permissions.PermUserUpdate), m.update)
	router.DELETE("/user/:id", m.requirePerm(permissions.PermUserDelete), m.delete)

	// Password management
	router.PUT("/user/:id/password", m.requirePerm(permissions.PermUserPasswordUpdate), m.updatePassword)

	// Authentication (internal API, typically called by auth module, requires user.read permission)
	router.POST("/user/authenticate", m.requirePerm(permissions.PermUserRead), m.authenticate)

	m.Logger().Info("Started " + ModuleName)
	return nil
}

func (m *UserAPIs) OnStop(ctx context.Context) error {
	m.Logger().Info("Stopped " + ModuleName)
	return nil
}
