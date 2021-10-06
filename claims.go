package protosign

import "github.com/dgrijalva/jwt-go"

type TokenClaims struct {
	Method string `json:"mtd"`
	Path   string `json:"pth"`
	jwt.StandardClaims
}
