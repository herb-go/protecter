package appsecretsign

import (
	"strconv"
	"time"

	"github.com/herb-go/herbsecurity/authority"
	"github.com/herb-go/herbsecurity/authority/credential"
	"github.com/herb-go/herbsecurity/authority/service/application"
	"github.com/herb-go/herbsecurity/secret"
	"github.com/herb-go/herbsecurity/secret/hasher/urlencodesign"
)

type Signer struct {
	Hasher        func(string) (string, error)
	Fields        map[credential.Name]string
	ByDesc        bool
	TimeOffsetMin *time.Duration
	TimeOffsetMax *time.Duration
}

func NewSigner() *Signer {
	return &Signer{
		Fields: map[credential.Name]string{},
	}
}
func (s *Signer) Sign(c credential.Credentials, secretdata secret.Secret) (string, error) {
	p := urlencodesign.NewParams()
	for k, v := range s.Fields {
		if k == credential.NameSecret {
			continue
		}
		value, err := c.Get(k)
		if err != nil {
			return "", err
		}
		p.Append(v, string(value))
	}
	return urlencodesign.Sign(s.Hasher, secretdata, s.Fields[credential.NameSecret], p, !s.ByDesc)
}
func (s *Signer) Verify(c credential.Credentials, secretdata secret.Secret) (bool, error) {
	timestamp, err := credential.LoadTimestamp(c)
	if err != nil {
		return false, err
	}
	if timestamp == "" {
		return false, nil
	}
	tsnumber, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return false, nil
	}
	sign, err := credential.LoadSign(c)
	if err != nil {
		return false, err
	}
	if sign == "" {
		return false, nil
	}
	now := time.Now()
	offset := now.Sub(time.Unix(tsnumber, 0))
	if s.TimeOffsetMax != nil {
		if offset > *s.TimeOffsetMax {
			return false, nil
		}
	}
	if s.TimeOffsetMin != nil {
		if offset < *s.TimeOffsetMin {
			return false, nil
		}
	}
	signed, err := s.Sign(c, secretdata)
	if err != nil {
		return false, err
	}
	if sign != signed {
		return false, nil
	}
	return true, nil
}

type Authenticator struct {
	Loader application.Loader
	Signer *Signer
}

func (a *Authenticator) Authenticate(c credential.Credentials) (*authority.Auth, error) {
	appid, err := credential.LoadAppID(c)
	if err != nil {
		return nil, err
	}
	v, err := a.Loader.LoadApplication(appid)
	if err != nil {
		return nil, err
	}
	auth := v.Auth()
	if !auth.Authenticated() {
		return auth, nil
	}
	ok, err := a.Signer.Verify(c, secret.Secret(v.Passphrase))
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	return auth, nil
}
func (a *Authenticator) DependencesData() (map[credential.Name]bool, error) {
	d := map[credential.Name]bool{
		credential.NameTimestamp: true,
		credential.NameSign:      true,
	}
	for k := range a.Signer.Fields {
		d[k] = true
	}
	return d, nil
}

func New() *Authenticator {
	return &Authenticator{
		Signer: NewSigner(),
	}
}
