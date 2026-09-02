package tokens

type TTokens struct {
	AccessToken  TAccessToken  `json:"access_token"`
	RefreshToken TRefreshToken `json:"refresh_token"`
}
