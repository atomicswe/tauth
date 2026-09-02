package terrors

import "errors"

var (
	ErrSecretKeyMissing = errors.New("TAUTH_SECRET_KEY must be set")
	TErrUserRequired    = errors.New("'user' must not be empty")
	TErrSubRequired     = errors.New("the 'sub' parameter is required")
	TErrRTExpTooLow     = errors.New("the expiration for the access token is too low, minimum is 5 minutes")
	TErrATExpTooLow     = errors.New("the expiration for the refresh token is too low, minimum is 1 minute")
)
