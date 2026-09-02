// Package terrors defines sentinel errors returned by tauth.
package terrors

import "errors"

var (
	TErrSecretKeyMissing            = errors.New("TAUTH_SECRET_KEY must be set")
	TErrUserRequired                = errors.New("'user' must not be empty")
	TErrSubRequired                 = errors.New("the 'sub' parameter is required")
	TErrRTExpTooLow                 = errors.New("the expiration for the access token is too low, minimum is 5 minutes")
	TErrATExpTooLow                 = errors.New("the expiration for the refresh token is too low, minimum is 1 minute")
	TErrTokensNotFound              = errors.New("the user does not have any stored tokens")
	TErrRefreshTokenMismatch        = errors.New("the provided refresh token does not match the stored one")
	TErrRefreshTokenExpired         = errors.New("the user's refresh token has expired")
	TErrFailedToExtractSub          = errors.New("the system failed to extract the 'sub' from the stored token")
	TErrFailedToExtractCustomClaims = errors.New("the system failed to extract the 'custom_claim' from the stored token")
	TErrUnexpectedClaimsType        = errors.New("the token has an unexpected claims type")
)
