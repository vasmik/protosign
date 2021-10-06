package token

import (
	"fmt"
	"net/http"
	"regexp"
)

/*
	Bearer implements Getter-Setter interface for Bearer token type
*/
type Bearer struct{}

// Get returns the Bearer authorization header value
func (t *Bearer) Get(r *http.Request) (string, error) {
	matchReg, _ := regexp.Compile("^Bearer (.*)$")
	tknBearer := matchReg.FindStringSubmatch(r.Header.Get("Authorization"))
	if len(tknBearer) < 2 || tknBearer[1] == "" {
		return "", fmt.Errorf("bearer token not found")
	}
	return tknBearer[1], nil
}

// Set sets the Bearer authorization header value
func (t *Bearer) Set(r *http.Request, token string) error {
	r.Header.Add("Authorization", "Bearer "+token)
	return nil
}
