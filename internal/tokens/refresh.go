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

type TRefreshToken struct {
	Token      string
	Expiration time.Duration
	ExpiresAt  time.Time
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
