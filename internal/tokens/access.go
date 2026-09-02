package tokens

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/atomicswe/tauth/pkg/terrors"
	"github.com/golang-jwt/jwt/v5"
)

const (
	defaultIssuer       = "tauth-default-iss"
	customClaimKey      = "custom_claim"
	defaultATExpiration = time.Minute * 5
)

type TAccessToken struct {
	Token     string
	ExpiresAt time.Time
}

// NewAccessToken generates a new access token
func NewAccessToken(user, sub string, expiration *time.Duration, customClaims string) (TAccessToken, error) {
	sub = strings.TrimSpace(sub)
	if sub == "" {
		return TAccessToken{}, terrors.TErrSubRequired
	}

	secret, found := os.LookupEnv("TAUTH_SECRET_KEY")
	if !found {
		return TAccessToken{}, terrors.ErrSecretKeyMissing
	}

	iss := defaultIssuer
	customIss, found := os.LookupEnv("TAUTH_ISS")
	if found {
		iss = customIss
	}

	exp := defaultATExpiration
	if expiration != nil {
		exp = *expiration
	}
	expiresAt := time.Now().Add(exp)

	claims := jwt.MapClaims{
		"iss": iss,
		"exp": expiresAt.Unix(),
		"sub": sub,
		"iat": time.Now(),
	}

	if customClaims != "" {
		claims[customClaimKey] = customClaims
	}

	token, err := jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		claims,
	).SignedString([]byte(secret))

	if err != nil {
		return TAccessToken{}, err
	}
	return TAccessToken{
		Token:     token,
		ExpiresAt: expiresAt,
	}, nil
}

// ValidateToken validates the token and returns
// the custom claims
func ValidateToken(token string) (string, error) {
	secret, found := os.LookupEnv("TAUTH_SECRET_KEY")
	if !found {
		return "", terrors.ErrSecretKeyMissing
	}

	iss := defaultIssuer
	customIss, found := os.LookupEnv("TAUTH_ISS")
	if found {
		iss = customIss
	}

	t, err := jwt.Parse(
		token,
		func(token *jwt.Token) (interface{}, error) {
			return []byte(secret), nil
		},
		jwt.WithIssuer(iss),
		jwt.WithLeeway(time.Minute),
		jwt.WithExpirationRequired(),
		jwt.WithValidMethods([]string{"HS256"}),
	)
	if err != nil {
		return "", fmt.Errorf("failed to validate the jwt token with: %w", err)
	}

	claims := t.Claims.(jwt.MapClaims)
	return claims[customClaimKey].(string), nil
}
