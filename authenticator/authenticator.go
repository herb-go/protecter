package authenticator

import "github.com/herb-go/herbsecurity/authority/credential"

type AuthenticatorFactory interface {
	CreateAuthenticator(func(interface{}) error) (credential.Authenticator, error)
}

type AuthenticatorFactoryFunc func(func(interface{}) error) (credential.Authenticator, error)

func (f AuthenticatorFactoryFunc) CreateAuthenticator(loader func(interface{}) error) (credential.Authenticator, error) {
	return f(loader)
}
