package token

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBearer_Get(t *testing.T) {
	tests := []struct {
		name    string
		header  http.Header
		want    string
		wantErr bool
	}{
		{name: "token exists", header: http.Header{"Authorization": []string{"Bearer TKN123"}}, want: "TKN123", wantErr: false},
		{name: "token exists", header: http.Header{"Authorization": []string{"Bearer"}}, want: "", wantErr: true},
		{name: "wrong type of auth header", header: http.Header{"Authorization": []string{"Basic blahblah"}}, want: "", wantErr: true},
		{name: "auth header missed", want: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &http.Request{Header: tt.header}
			tkn := &Bearer{}
			got, err := tkn.Get(r)
			if tt.wantErr {
				assert.NotNil(t, err)
				return
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestBearer_Set(t *testing.T) {
	tkn := &Bearer{}
	r, _ := http.NewRequest("GET", "/some/path", nil)
	tkn.Set(r, "TOKEN")
	assert.Equal(t, "Bearer TOKEN", r.Header.Get("Authorization"))
}
