package examples

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/atomicswe/tauth/internal/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIssueTokensExampleSucceeds(t *testing.T) {
	t.Setenv("TAUTH_SECRET_KEY", "very-secret-secret-key")

	user := "some_user"
	tokens, err := NewTokens(user)
	require.NoError(t, err)

	assert.NotEmpty(t, tokens.AccessToken.Token)
	assert.NotEmpty(t, tokens.RefreshToken.Token)

	tokensString, err := json.MarshalIndent(tokens, "", "\t")
	require.NoError(t, err)
	fmt.Printf("issued tokens: %s\n", tokensString)

	cached, err := memory.Live.Get(user)
	require.NoError(t, err)
	assert.Equal(t, tokens, cached)
}
