package examples

import (
	"testing"

	"github.com/atomicswe/tauth"
	"github.com/atomicswe/tauth/internal/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRefreshTokensExampleSucceeds(t *testing.T) {
	t.Setenv("TAUTH_SECRET_KEY", "very-secret-secret-key")

	user := "refresh-example-user"
	oldTokens, newTokens, err := RefreshTokens(user)
	require.NoError(t, err)

	assert.NotEmpty(t, oldTokens.AccessToken.Token)
	assert.NotEmpty(t, oldTokens.RefreshToken.Token)
	assert.NotEmpty(t, newTokens.AccessToken.Token)
	assert.NotEmpty(t, newTokens.RefreshToken.Token)

	assert.NotEqual(t, oldTokens.AccessToken.Token, newTokens.AccessToken.Token)
	assert.NotEqual(t, oldTokens.RefreshToken.Token, newTokens.RefreshToken.Token)
	assert.Equal(t, oldTokens.AccessToken.Expiration, newTokens.AccessToken.Expiration)
	assert.Equal(t, oldTokens.RefreshToken.Expiration, newTokens.RefreshToken.Expiration)

	gotUser, customClaims, err := tauth.ValidateToken(newTokens.AccessToken.Token)
	require.NoError(t, err)
	assert.Equal(t, user, gotUser)
	assert.JSONEq(t, `{"purpose":"example"}`, customClaims)

	_, _, err = tauth.ValidateToken(oldTokens.AccessToken.Token)
	require.NoError(t, err)

	cached, err := memory.Live.Get(user)
	require.NoError(t, err)
	assert.Equal(t, newTokens, cached)

	t.Logf("old access token: %s", oldTokens.AccessToken.Token)
	t.Logf("new access token: %s", newTokens.AccessToken.Token)
	t.Logf("old refresh token: %s", oldTokens.RefreshToken.Token)
	t.Logf("new refresh token: %s", newTokens.RefreshToken.Token)
}
