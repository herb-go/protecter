package protecter

import (
	"testing"

	"github.com/herb-go/herbsecurity/authorize/role"
)

func TestLoader(t *testing.T) {
	l := RoleRolesLoader(role.NewRoles(role.NewRole("test")))
	pl := RolePolicyLoader(role.NewRoles(role.NewRole("test")))
	pl2 := RolePolicyLoader(role.NewRoles(role.NewRole("test2")))
	ok, err := Authorize(nil, l, pl)
	if ok != true || err != nil {
		t.Fatal(ok, err)
	}
	ok, err = Authorize(nil, l, pl2)
	if ok != false || err != nil {
		t.Fatal(ok, err)
	}
}
