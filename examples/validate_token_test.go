package examples

import (
	"encoding/json"
	"testing"

	"github.com/atomicswe/tauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateTokenExampleSucceeds(t *testing.T) {
	t.Setenv("TAUTH_SECRET_KEY", "very-secret-secret-key")

	user := "validate-example-user"
	gotUser, rawClaims, err := ValidateToken(user)
	require.NoError(t, err)
	assert.Equal(t, user, gotUser)

	var claims map[string]string
	require.NoError(t, json.Unmarshal([]byte(rawClaims), &claims))
	assert.Equal(t, "example", claims["purpose"])

	t.Logf("user: %s", gotUser)
	t.Logf("custom claims: %s", rawClaims)
}

func TestValidateTokenExampleRejectsRefreshToken(t *testing.T) {
	t.Setenv("TAUTH_SECRET_KEY", "very-secret-secret-key")

	issued, err := IssueTokens("validate-refresh-token-user")
	require.NoError(t, err)

	_, _, err = tauth.ValidateToken(issued.RefreshToken.Token)
	require.Error(t, err)
}
