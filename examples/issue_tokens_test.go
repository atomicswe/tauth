package examples

import (
	"testing"
	"time"

	"github.com/atomicswe/tauth"
	"github.com/atomicswe/tauth/internal/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIssueTokensExampleSucceeds(t *testing.T) {
	t.Setenv("TAUTH_SECRET_KEY", "very-secret-secret-key")

	user := "issue-example-user"
	issued, err := IssueTokens(user)
	require.NoError(t, err)

	assert.NotEmpty(t, issued.AccessToken.Token)
	assert.NotEmpty(t, issued.RefreshToken.Token)
	assert.Equal(t, 15*time.Minute, issued.AccessToken.Expiration)
	assert.Equal(t, 48*time.Hour, issued.RefreshToken.Expiration)
	assert.True(t, issued.AccessToken.ExpiresAt.After(time.Now()))
	assert.True(t, issued.RefreshToken.ExpiresAt.After(time.Now()))

	gotUser, customClaims, err := tauth.ValidateToken(issued.AccessToken.Token)
	require.NoError(t, err)
	assert.Equal(t, user, gotUser)
	assert.JSONEq(t, `{"purpose":"example"}`, customClaims)

	cached, err := memory.Live.Get(user)
	require.NoError(t, err)
	assert.Equal(t, issued, cached)

	t.Logf("access token: %s", issued.AccessToken.Token)
	t.Logf("refresh token: %s", issued.RefreshToken.Token)
	t.Logf("access token expires at: %s", issued.AccessToken.ExpiresAt.Format(time.RFC3339))
}
