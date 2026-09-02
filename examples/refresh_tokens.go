package examples

import (
	"github.com/atomicswe/tauth"
	"github.com/atomicswe/tauth/internal/tokens"
)

func RefreshTokens(user string) (tokens.TTokens, tokens.TTokens, error) {
	oldTokens, err := IssueTokens(user)
	if err != nil {
		return tokens.TTokens{}, tokens.TTokens{}, err
	}

	refreshedTokens, err := tauth.RefreshTokens(user, oldTokens.RefreshToken.Token)
	if err != nil {
		return tokens.TTokens{}, tokens.TTokens{}, err
	}

	return oldTokens, refreshedTokens, nil
}
