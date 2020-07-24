package httprole

import (
	"net/http"

	"github.com/herb-go/herbsecurity/authorize/role"
)

type RolesLoader interface {
	LoadRoles(r *http.Request) (*role.Roles, error)
}

type RolesLoaderFunc func(r *http.Request) (*role.Roles, error)

func (f RolesLoaderFunc) LoadRoles(r *http.Request) (*role.Roles, error) {
	return f(r)
}

func RoleRolesLoader(rl role.RolesLoader) RolesLoader {
	return RolesLoaderFunc(func(r *http.Request) (*role.Roles, error) {
		return rl.LoadRoles()
	})
}

type PolicyLoader interface {
	LoadPolicy(r *http.Request) (role.Policy, error)
}

type PolicyLoaderFunc func(r *http.Request) (role.Policy, error)

func (f PolicyLoaderFunc) LoadPolicy(r *http.Request) (role.Policy, error) {
	return f(r)
}

func RolePolicyLoader(roles role.Policy) PolicyLoader {
	return PolicyLoaderFunc(func(r *http.Request) (role.Policy, error) {
		return roles, nil
	})
}

func Authorize(r *http.Request, rl RolesLoader, pls ...PolicyLoader) (bool, error) {
	roles, err := rl.LoadRoles(r)
	if err != nil {
		return false, err
	}
	p := make([]role.Policy, len(pls))
	for k := range pls {
		p[k], err = pls[k].LoadPolicy(r)
		if err != nil {
			return false, err
		}
	}
	return role.Authorize(roles, p...)
}
