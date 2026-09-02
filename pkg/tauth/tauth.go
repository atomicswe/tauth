package tauth

import (
	"strings"
	"time"

	"github.com/atomicswe/tauth/internal/memory"
	"github.com/atomicswe/tauth/internal/tokens"
	"github.com/atomicswe/tauth/pkg/terrors"
)

const (
	minATExpiration = time.Minute * 5
	minRTExpiration = time.Hour
)

type TAuthOptions struct {
	Sub          string         `json:"sub"`
	ATExpiration *time.Duration `json:"at_expiration"`
	RTExpiration *time.Duration `json:"rt_expiration"`
	CustomClaims string         `json:"custom_claim"`
}

func IssueTokens(user string, options TAuthOptions) (tokens.TTokens, error) {
	user = strings.TrimSpace(user)
	if user == "" {
		return tokens.TTokens{}, terrors.TErrUserRequired
	}

	if err := validateOptions(options); err != nil {
		return tokens.TTokens{}, err
	}

	at, err := tokens.NewAccessToken(user, options.Sub, options.ATExpiration, options.CustomClaims)
	if err != nil {
		return tokens.TTokens{}, err
	}

	rt, err := tokens.NewRefreshToken(options.RTExpiration)
	if err != nil {
		return tokens.TTokens{}, err
	}

	issuedTokens := tokens.TTokens{
		AccessToken:  at,
		RefreshToken: rt,
	}
	memory.Live.Put(user, issuedTokens)
	return issuedTokens, nil
}

func validateOptions(options TAuthOptions) error {
	options.Sub = strings.TrimSpace(options.Sub)
	if options.Sub == "" {
		return terrors.TErrSubRequired
	}
	if options.ATExpiration != nil && *options.ATExpiration < minATExpiration {
		return terrors.TErrRTExpTooLow
	}
	if options.RTExpiration != nil && *options.RTExpiration < minRTExpiration {
		return terrors.TErrRTExpTooLow
	}
	options.CustomClaims = strings.TrimSpace(options.CustomClaims)
	return nil
}

func RefreshTokens(user string, refreshToken string) (tokens.TTokens, error) {
	user = strings.TrimSpace(user)
	if user == "" {
		return tokens.TTokens{}, terrors.TErrUserRequired
	}

	oldTokens, err := memory.Live.Get(user)
	if err != nil {
		return tokens.TTokens{}, err
	}

	if refreshToken != oldTokens.RefreshToken.Token {
		return tokens.TTokens{}, terrors.TErrRefreshTokenMismatch
	}

	if oldTokens.RefreshToken.ExpiresAt.Before(time.Now()) {
		return tokens.TTokens{}, terrors.TErrRefreshTokenExpired
	}

	sub, err := tokens.ExtractSub(oldTokens.AccessToken.Token)
	if err != nil {
		return tokens.TTokens{}, err // terrors.TErrFailedToExtractSub
	}

	customClaims, err := tokens.ExtractCustomClaims(oldTokens.AccessToken.Token)
	if err != nil {
		return tokens.TTokens{}, err // terrors.TErrFailedToExtractCustomClaims
	}

	return IssueTokens(user, TAuthOptions{
		Sub:          sub,
		ATExpiration: &oldTokens.AccessToken.Expiration,
		RTExpiration: &oldTokens.RefreshToken.Expiration,
		CustomClaims: customClaims,
	})
}
