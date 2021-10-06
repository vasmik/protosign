package keychain

import "context"

// Provider interface to get RSA keys
type Provider interface {
	GetPublicKey(ctx context.Context, issuer string) ([]byte, error)
}
