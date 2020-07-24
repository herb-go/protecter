package protecter

import (
	"github.com/herb-go/herbsecurity/authority"
	"github.com/herb-go/herbsecurity/authorize/role"
)

type Context struct {
	Auth      *authority.Auth
	Protecter *Protecter
	Roles     *role.Roles
}

func NewContext() *Context {
	return &Context{
		Roles: role.NewRoles(),
	}
}
