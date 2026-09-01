package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	defaultIssuer       = "tauth-default-iss"
	customClaimKey      = "custom_claim"
	defaultATExpiration = time.Minute * 5
)

var (
	ErrSubRequired      = errors.New("the 'sub' parameter is required")
	ErrSecretKeyMissing = errors.New("TAUTH_SECRET_KEY must be set")
)

type CustomClaim struct {
	User  string `json:"user"`  // the user identifier (i.e.: a username, uuid or email)
	Other string `json:"other"` // any other custom claim that should be in the token
}

// NewAccessToken generates a new access token
func NewAccessToken(sub string, expiration *time.Duration, customClaim *CustomClaim) (string, error) {
	sub = strings.TrimSpace(sub)
	if sub == "" {
		return "", ErrSubRequired
	}

	secret, found := os.LookupEnv("TAUTH_SECRET_KEY")
	if !found {
		return "", ErrSecretKeyMissing
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

	claims := jwt.MapClaims{
		"iss": iss,
		"exp": time.Now().Add(exp).Unix(),
		"sub": sub,
		"iat": time.Now(),
	}

	if customClaim != nil {
		data, err := json.MarshalIndent(*customClaim, "", "\t")
		if err != nil {
			return "", err
		}
		claims[customClaimKey] = data
	}

	token, err := jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		claims,
	).SignedString([]byte(secret))

	if err != nil {
		return "", err
	}
	return token, nil
}

// ValidateToken validates the token and returns
// the parsed CustomClaim
func ValidateToken(token string) (CustomClaim, error) {
	secret, found := os.LookupEnv("TAUTH_SECRET_KEY")
	if !found {
		return CustomClaim{}, ErrSecretKeyMissing
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
		return CustomClaim{}, fmt.Errorf("failed to validate the jwt token with: %w", err)
	}

	claims := t.Claims.(jwt.MapClaims)
	var decoded CustomClaim
	if err := json.Unmarshal([]byte(claims[customClaimKey].(string)), &decoded); err != nil {
		return CustomClaim{}, err
	}
	return decoded, nil
}
