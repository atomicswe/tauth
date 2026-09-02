package examples

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/atomicswe/tauth/internal/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRefreshTokensExampleSucceeds(t *testing.T) {
	t.Setenv("TAUTH_SECRET_KEY", "very-secret-secret-key")

	user := "some_user"
	old, new, err := RefreshTokens(user)
	require.NoError(t, err)

	assert.NotEmpty(t, old.AccessToken.Token)
	assert.NotEmpty(t, old.RefreshToken.Token)

	oldTokensString, err := json.MarshalIndent(old, "", "\t")
	require.NoError(t, err)
	fmt.Printf("old tokens: %s\n", oldTokensString)

	newTokensString, err := json.MarshalIndent(new, "", "\t")
	require.NoError(t, err)
	fmt.Printf("new tokens: %s\n", newTokensString)

	cached, err := memory.Live.Get(user)
	require.NoError(t, err)
	assert.Equal(t, new, cached)
}
