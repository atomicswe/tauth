package tauth

import (
	"github.com/atomicswe/tauth/internal/tokens"
)

type TTokens struct {
	AccessToken  tokens.TAccessToken
	RefreshToken tokens.TRefreshToken
}
