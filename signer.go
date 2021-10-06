package protosign

import (
	"errors"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/vasmik/protosign/token"
)

type TokenSetter interface {
	Set(r *http.Request, token string) error
}

type Signer struct {
	Issuer        string
	PrivateRSAKey string
	TTL           time.Duration
	TokenSetter   TokenSetter
}

func (s *Signer) Sign(r *http.Request, subject string) error {
	if s.Issuer == "" {
		return errors.New("no issuer specified")
	}
	if s.PrivateRSAKey == "" {
		return errors.New("np private rsa key specified")
	}
	if s.TokenSetter == nil {
		s.TokenSetter = &token.Bearer{}
	}
	if s.TTL == 0 {
		s.TTL = 1 * time.Second
	}
	claims := TokenClaims{
		Method: r.Method,
		Path:   r.URL.Path,
		StandardClaims: jwt.StandardClaims{
			Issuer:    s.Issuer,
			Subject:   subject,
			ExpiresAt: time.Now().Add(s.TTL).Unix(),
		},
	}
	signKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(s.PrivateRSAKey))
	if err != nil {
		return err
	}
	signedTkn, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(signKey)
	if err != nil {
		return err
	}
	s.TokenSetter.Set(r, signedTkn)
	return nil
}
