package examples

import (
	"encoding/json"
	"time"

	"github.com/atomicswe/tauth"
	"github.com/atomicswe/tauth/internal/tokens"
)

func exampleOptions() (tauth.TAuthOptions, error) {
	customClaims, err := json.Marshal(map[string]string{
		"purpose": "example",
	})
	if err != nil {
		return tauth.TAuthOptions{}, err
	}

	atExpiration := 15 * time.Minute
	rtExpiration := 48 * time.Hour

	return tauth.TAuthOptions{
		Sub:          "example-client",
		ATExpiration: &atExpiration,
		RTExpiration: &rtExpiration,
		CustomClaims: string(customClaims),
	}, nil
}

func IssueTokens(user string) (tokens.TTokens, error) {
	options, err := exampleOptions()
	if err != nil {
		return tokens.TTokens{}, err
	}

	return tauth.IssueTokens(user, options)
}
