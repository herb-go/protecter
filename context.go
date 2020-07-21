package protecter

import (
	"github.com/herb-go/herbsecurity/authority"
)

type Context struct {
	Auth      *authority.Auth
	Protecter *Protecter
}

func NewContext() *Context {
	return &Context{}
}
