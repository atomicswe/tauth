package examples

import (
	"encoding/json"
	"time"

	"github.com/atomicswe/tauth/internal/tokens"
	"github.com/atomicswe/tauth/pkg/tauth"
)

func RefreshTokens(user string) (tokens.TTokens, tokens.TTokens, error) {
	customClaims, err := json.Marshal(map[string]string{
		"purpose": "example",
	})
	if err != nil {
		return tokens.TTokens{}, tokens.TTokens{}, err
	}

	oldTokens, err := tauth.IssueTokens(user, tauth.TAuthOptions{
		Sub:          "some_sub",
		CustomClaims: string(customClaims),
	})
	if err != nil {
		return tokens.TTokens{}, tokens.TTokens{}, err
	}

	time.Sleep(time.Second * 5) // simulate actual time passing

	refreshedTokens, err := tauth.RefreshTokens(user, oldTokens.RefreshToken.Token)
	if err != nil {
		return tokens.TTokens{}, tokens.TTokens{}, err
	}

	return oldTokens, refreshedTokens, nil
}
