package examples

import (
	"encoding/json"

	"github.com/atomicswe/tauth/internal/tokens"
	"github.com/atomicswe/tauth/pkg/tauth"
)

func NewTokens(user string) (tokens.TTokens, error) {
	customClaims, err := json.Marshal(map[string]string{
		"purpose": "example",
	})
	if err != nil {
		return tokens.TTokens{}, err
	}

	return tauth.IssueTokens(user, tauth.TAuthOptions{
		Sub:          "some_sub",
		CustomClaims: string(customClaims),
	})
}
