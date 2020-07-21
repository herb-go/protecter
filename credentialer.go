package protecter

import (
	"net/http"

	"github.com/herb-go/herbsecurity/authority/credential"
)

type Credentialer interface {
	CredentialRequest(r *http.Request) credential.CredentialSource
}

type CredentialerFunc func(r *http.Request) credential.CredentialSource

func (f CredentialerFunc) CredentialRequest(r *http.Request) credential.CredentialSource {
	return f(r)
}
