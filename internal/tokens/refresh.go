package tokens

import (
	"math/rand"
	"time"
)

const (
	refreshtTokenSize = 32
	chars             = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789"

	defaultRTExpiration = time.Hour * 24
)

// TRefreshToken is an opaque refresh token together with its lifetime.
type TRefreshToken struct {
	// Token is the opaque refresh-token string.
	Token string
	// Expiration is the lifetime used when the token was issued.
	Expiration time.Duration
	// ExpiresAt is the instant after which the token is expired.
	ExpiresAt time.Time
}

// NewRefreshToken creates a random refresh token.
func NewRefreshToken(expiration *time.Duration) (TRefreshToken, error) {
	b := make([]byte, refreshtTokenSize)
	for i := range b {
		b[i] = chars[rand.Intn(len(chars))]
	}

	exp := defaultRTExpiration
	if expiration != nil {
		exp = *expiration
	}

	return TRefreshToken{
		Token:      string(b),
		Expiration: exp,
		ExpiresAt:  time.Now().Add(exp),
	}, nil
}
