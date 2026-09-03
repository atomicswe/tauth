// Package tauth issues HS256 JWT access tokens and opaque refresh tokens.
//
// Signing and validation require the TAUTH_SECRET_KEY environment variable.
// Set TAUTH_ISS to override the JWT issuer; the default is tauth-default-iss.
// Issued refresh tokens are kept in process memory and checked by RefreshTokens.
package tauth

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/atomicswe/tauth/internal/common"
	"github.com/atomicswe/tauth/internal/memory"
	"github.com/atomicswe/tauth/internal/tokens"
	"github.com/atomicswe/tauth/pkg/terrors"
	"github.com/golang-jwt/jwt/v5"
)

const (
	minATExpiration = time.Minute * 5
	minRTExpiration = time.Hour
)

// Tokens is the access and refresh pair returned by IssueTokens and RefreshTokens.
type Tokens = tokens.TTokens

// AccessToken is a signed JWT together with its configured lifetime and expiry instant.
type AccessToken = tokens.TAccessToken

// RefreshToken is an opaque refresh token together with its configured lifetime and expiry instant.
type RefreshToken = tokens.TRefreshToken

// TAuthOptions configures token issuance for [IssueTokens].
type TAuthOptions struct {
	// [Optional] ATExpiration is the access-token lifetime.
	ATExpiration *time.Duration `json:"at_expiration"`
	// [Optional] RTExpiration is the refresh-token lifetime.
	RTExpiration *time.Duration `json:"rt_expiration"`
	// [Optional] CustomClaims is an optional string stored in the JWT as custom_claim.
	CustomClaims string `json:"custom_claim"`
}

// IssueTokens creates an access token and a refresh token for user.
func IssueTokens(user string, options TAuthOptions) (Tokens, error) {
	user = strings.TrimSpace(user)
	if user == "" {
		return Tokens{}, terrors.TErrUserRequired
	}

	if err := validateOptions(options); err != nil {
		return Tokens{}, err
	}

	at, err := tokens.NewAccessToken(user, options.ATExpiration, options.CustomClaims)
	if err != nil {
		return Tokens{}, err
	}

	rt, err := tokens.NewRefreshToken(options.RTExpiration)
	if err != nil {
		return Tokens{}, err
	}

	issuedTokens := Tokens{
		AccessToken:  at,
		RefreshToken: rt,
	}
	memory.Live.Put(user, issuedTokens)
	return issuedTokens, nil
}

func validateOptions(options TAuthOptions) error {
	if options.ATExpiration != nil && *options.ATExpiration < minATExpiration {
		return terrors.TErrRTExpTooLow
	}
	if options.RTExpiration != nil && *options.RTExpiration < minRTExpiration {
		return terrors.TErrRTExpTooLow
	}
	options.CustomClaims = strings.TrimSpace(options.CustomClaims)
	return nil
}

// ValidateToken parses and validates a JWT access token.
func ValidateToken(token string) (string, string, error) {
	secret, found := os.LookupEnv("TAUTH_SECRET_KEY")
	if !found {
		return "", "", terrors.TErrSecretKeyMissing
	}

	iss := common.DefaultIssuer
	if customIss, found := os.LookupEnv("TAUTH_ISS"); found {
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
		return "", "", fmt.Errorf("failed to validate the jwt token with: %w", err)
	}

	claims, ok := t.Claims.(jwt.MapClaims)
	if !ok {
		return "", "", terrors.TErrUnexpectedClaimsType
	}

	user, _ := claims["user"].(string)
	customClaims, _ := claims[common.CustomClaimKey].(string)
	return user, customClaims, nil
}

// RefreshTokens validates the user's stored refresh token and issues a new pair.
func RefreshTokens(user string, refreshToken string) (Tokens, error) {
	user = strings.TrimSpace(user)
	if user == "" {
		return Tokens{}, terrors.TErrUserRequired
	}

	oldTokens, err := memory.Live.Get(user)
	if err != nil {
		return Tokens{}, err
	}

	if refreshToken != oldTokens.RefreshToken.Token {
		return Tokens{}, terrors.TErrRefreshTokenMismatch
	}

	if oldTokens.RefreshToken.ExpiresAt.Before(time.Now()) {
		return Tokens{}, terrors.TErrRefreshTokenExpired
	}

	customClaims, err := tokens.ExtractCustomClaims(oldTokens.AccessToken.Token)
	if err != nil {
		return Tokens{}, terrors.TErrFailedToExtractCustomClaims
	}

	return IssueTokens(user, TAuthOptions{
		ATExpiration: &oldTokens.AccessToken.Expiration,
		RTExpiration: &oldTokens.RefreshToken.Expiration,
		CustomClaims: customClaims,
	})
}
