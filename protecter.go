package protecter

import (
	"net/http"

	"github.com/herb-go/herbsecurity/authority/credential"
)

var DefaultOnFail = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	http.Error(w, http.StatusText(403), 403)
})

var DefaultAuthenticator = credential.ForbiddenAuthenticator

type Protecter struct {
	Credentialers []Credentialer
	Authenticator credential.Authenticator
	OnFail        http.Handler
}

func (p *Protecter) WithOnFail(h http.Handler) *Protecter {
	p.OnFail = h
	return p
}

func (p *Protecter) WithCredentialers(c ...Credentialer) *Protecter {
	p.Credentialers = c
	return p
}

func (p *Protecter) WithAuthenticator(a credential.Authenticator) *Protecter {
	p.Authenticator = a
	return p
}
func (p *Protecter) Reset() {
	p.Authenticator = DefaultAuthenticator
	p.OnFail = DefaultOnFail
	p.Credentialers = []Credentialer{}
}
func New() *Protecter {
	p := &Protecter{
		Authenticator: DefaultAuthenticator,
		OnFail:        DefaultOnFail,
	}
	return p
}

var ForbiddenProtecter = New()

var DefaultProtecter = ForbiddenProtecter

var NotWorkingProtecter = &Protecter{
	Authenticator: credential.FixedAuthenticator("notworking"),
	OnFail:        DefaultOnFail,
}
