package tokens

import (
	"os"
	"strings"
	"time"

	"github.com/atomicswe/tauth/internal/common"
	"github.com/atomicswe/tauth/pkg/terrors"
	"github.com/golang-jwt/jwt/v5"
)

const (
	defaultATExpiration = time.Minute * 5
)

type TAccessToken struct {
	Token      string
	Expiration time.Duration
	ExpiresAt  time.Time
}

// NewAccessToken generates a new access token
func NewAccessToken(user, sub string, expiration *time.Duration, customClaims string) (TAccessToken, error) {
	sub = strings.TrimSpace(sub)
	if sub == "" {
		return TAccessToken{}, terrors.TErrSubRequired
	}

	secret, found := os.LookupEnv("TAUTH_SECRET_KEY")
	if !found {
		return TAccessToken{}, terrors.TErrSecretKeyMissing
	}

	iss := common.DefaultIssuer
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
		"iss":  iss,
		"exp":  expiresAt.Unix(),
		"sub":  sub,
		"iat":  time.Now(),
		"user": user,
	}

	if customClaims != "" {
		claims[common.CustomClaimKey] = customClaims
	}

	token, err := jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		claims,
	).SignedString([]byte(secret))

	if err != nil {
		return TAccessToken{}, err
	}
	return TAccessToken{
		Token:      token,
		Expiration: exp,
		ExpiresAt:  expiresAt,
	}, nil
}

func ExtractSub(token string) (string, error) {
	secret, found := os.LookupEnv("TAUTH_SECRET_KEY")
	if !found {
		return "", terrors.TErrSecretKeyMissing
	}

	t, err := jwt.Parse(
		token,
		func(token *jwt.Token) (interface{}, error) {
			return []byte(secret), nil
		},
		jwt.WithValidMethods([]string{"HS256"}),
	)
	if err != nil {
		return "", err
	}

	return t.Claims.GetSubject()
}

func ExtractCustomClaims(token string) (string, error) {
	secret, found := os.LookupEnv("TAUTH_SECRET_KEY")
	if !found {
		return "", terrors.TErrSecretKeyMissing
	}

	t, err := jwt.Parse(
		token,
		func(token *jwt.Token) (interface{}, error) {
			return []byte(secret), nil
		},
		jwt.WithValidMethods([]string{"HS256"}),
	)
	if err != nil {
		return "", err
	}

	claims := t.Claims.(jwt.MapClaims)
	return claims[common.CustomClaimKey].(string), nil
}
