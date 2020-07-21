package appsecret

import (
	"github.com/herb-go/herbsecurity/authority"
	"github.com/herb-go/herbsecurity/authority/credential"
	"github.com/herb-go/herbsecurity/authority/service/application"
)

type Authenticator struct {
	Loader application.Loader
}

func (a *Authenticator) Authenticate(c credential.Credentials) (*authority.Auth, error) {
	appid, err := credential.LoadAppID(c)
	if err != nil {
		return nil, err
	}
	secret, err := credential.LoadSecret(c)
	if err != nil {
		return nil, err
	}
	v, err := a.Loader.LoadApplication(appid)
	if err != nil {
		return nil, err
	}
	if v == nil {
		return nil, nil
	}
	if v.Passphrase == "" || v.Passphrase != secret {
		return nil, err
	}
	return v.Auth(), nil
}
func (a *Authenticator) DependencesData() (map[credential.Name]bool, error) {
	return map[credential.Name]bool{
		credential.NameAppID:  true,
		credential.NameSecret: true,
	}, nil
}

func New() *Authenticator {
	return &Authenticator{}
}
