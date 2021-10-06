package protosign

import (
	"context"
	"fmt"
	"net/http"

	"github.com/dgrijalva/jwt-go"
	"github.com/vasmik/protosign/keychain"
	"github.com/vasmik/protosign/token"
)

type TokenExtractor interface {
	Get(r *http.Request) (string, error)
}

type SignatureValidator struct {
	Subject     string
	KeyProvider keychain.Provider
	Token       TokenExtractor
	OnError     func(rw http.ResponseWriter, r *http.Request, err error)
}

func (s *SignatureValidator) SignedRequestHandler() func(next http.Handler) http.Handler {
	if s.Subject == "" {
		panic(fmt.Errorf("SignatureValidator subject missed"))
	}
	if s.KeyProvider == nil {
		panic(fmt.Errorf("SignatureValidator key provider missed"))
	}
	if s.Token == nil {
		s.Token = &token.Bearer{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			authToken, err := s.Token.Get(r)
			if err != nil {
				s.handleError(rw, r, err)
				return
			}
			tkn, err := jwt.ParseWithClaims(authToken, &TokenClaims{}, keyFunc(r.Context(), s.KeyProvider))
			if err != nil {
				s.handleError(rw, r, err)
				return
			}
			claims := tkn.Claims.(*TokenClaims)
			if r.Method != claims.Method || r.URL.Path != claims.Path || claims.Subject != s.Subject {
				s.handleError(rw, r, err)
				return
			}
			next.ServeHTTP(rw, r)
		})
	}
}

func (s *SignatureValidator) handleError(rw http.ResponseWriter, r *http.Request, err error) {
	if s.OnError != nil {
		s.OnError(rw, r, err)
		return
	}
	rw.WriteHeader(http.StatusUnauthorized)
}

func keyFunc(ctx context.Context, keysProvider keychain.Provider) func(t *jwt.Token) (interface{}, error) {
	return func(t *jwt.Token) (interface{}, error) {
		if err := t.Claims.Valid(); err != nil {
			return nil, err
		}
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		claims, ok := t.Claims.(*TokenClaims)
		if !ok {
			return nil, fmt.Errorf("wrong token structure")
		}
		rsaKey, err := keysProvider.GetPublicKey(ctx, claims.Issuer)
		if err != nil {
			return nil, fmt.Errorf("can't find public key for service %s: %v", claims.Issuer, err)
		}
		key, err := jwt.ParseRSAPublicKeyFromPEM([]byte(rsaKey))
		if err != nil {
			return nil, err
		}
		return key, nil
	}
}
