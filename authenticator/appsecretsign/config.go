package appsecretsign

import (
	"time"

	"github.com/herb-go/herbsecurity/authority/credential"
	"github.com/herb-go/herbsecurity/secret/hasher"
)

type SignerConfig struct {
	Hash                  string
	Fields                map[string]string
	ByDesc                bool
	TimeOffsetMinInSecond *int64
	TimeOffsetMaxInSecond *int64
}

func (c *SignerConfig) Load() (*Signer, error) {
	h, err := hasher.GetHasher(c.Hash)
	if err != nil {
		return nil, err
	}
	s := NewSigner()
	s.Hasher = h
	s.ByDesc = c.ByDesc
	for k := range c.Fields {
		s.Fields[credential.Name(k)] = c.Fields[k]
	}
	if c.TimeOffsetMaxInSecond != nil {
		tmax := time.Duration(*c.TimeOffsetMaxInSecond) * time.Second
		s.TimeOffsetMax = &tmax
	}
	if c.TimeOffsetMinInSecond != nil {
		tmin := time.Duration(*c.TimeOffsetMinInSecond) * time.Second
		s.TimeOffsetMin = &tmin
	}
	return s, nil
}
