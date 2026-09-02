package tokens

import (
	"os"
	"testing"
	"time"

	"github.com/atomicswe/tauth/internal/common"
	"github.com/atomicswe/tauth/pkg/terrors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testSecret = "test-secret-key"

func setSecret(t *testing.T) {
	t.Helper()
	t.Setenv("TAUTH_SECRET_KEY", testSecret)
}

func unsetSecret(t *testing.T) {
	t.Helper()
	t.Setenv("TAUTH_SECRET_KEY", testSecret)
	require.NoError(t, os.Unsetenv("TAUTH_SECRET_KEY"))
}

func TestNewAccessTokenSucceeds(t *testing.T) {
	setSecret(t)

	exp := 15 * time.Minute
	before := time.Now()
	got, err := NewAccessToken("alice", "test-client", &exp, `{"role":"admin"}`)
	require.NoError(t, err)

	assert.NotEmpty(t, got.Token)
	assert.Equal(t, exp, got.Expiration)
	assert.True(t, got.ExpiresAt.After(before))
	assert.True(t, got.ExpiresAt.Before(time.Now().Add(exp+time.Second)))

	parsed, err := jwt.Parse(got.Token, func(token *jwt.Token) (interface{}, error) {
		return []byte(testSecret), nil
	})
	require.NoError(t, err)

	claims, ok := parsed.Claims.(jwt.MapClaims)
	require.True(t, ok)
	assert.Equal(t, common.DefaultIssuer, claims["iss"])
	assert.Equal(t, "test-client", claims["sub"])
	assert.Equal(t, "alice", claims["user"])
	assert.Equal(t, `{"role":"admin"}`, claims[common.CustomClaimKey])
}

func TestNewAccessTokenUsesDefaultExpiration(t *testing.T) {
	setSecret(t)

	got, err := NewAccessToken("alice", "test-client", nil, "")
	require.NoError(t, err)
	assert.Equal(t, defaultATExpiration, got.Expiration)
}

func TestNewAccessTokenUsesCustomIssuer(t *testing.T) {
	setSecret(t)
	t.Setenv("TAUTH_ISS", "custom-issuer")

	got, err := NewAccessToken("alice", "test-client", nil, "")
	require.NoError(t, err)

	parsed, err := jwt.Parse(got.Token, func(token *jwt.Token) (interface{}, error) {
		return []byte(testSecret), nil
	})
	require.NoError(t, err)
	claims := parsed.Claims.(jwt.MapClaims)
	assert.Equal(t, "custom-issuer", claims["iss"])
}

func TestNewAccessTokenTrimsSub(t *testing.T) {
	setSecret(t)

	got, err := NewAccessToken("alice", "  test-client  ", nil, "")
	require.NoError(t, err)

	sub, err := ExtractSub(got.Token)
	require.NoError(t, err)
	assert.Equal(t, "test-client", sub)
}

func TestNewAccessTokenRequiresSub(t *testing.T) {
	_, err := NewAccessToken("alice", "  ", nil, "")
	require.ErrorIs(t, err, terrors.TErrSubRequired)
}

func TestNewAccessTokenRequiresSecret(t *testing.T) {
	unsetSecret(t)

	_, err := NewAccessToken("alice", "test-client", nil, "")
	require.ErrorIs(t, err, terrors.TErrSecretKeyMissing)
}

func TestExtractSub(t *testing.T) {
	setSecret(t)

	got, err := NewAccessToken("alice", "test-client", nil, "")
	require.NoError(t, err)

	sub, err := ExtractSub(got.Token)
	require.NoError(t, err)
	assert.Equal(t, "test-client", sub)
}

func TestExtractSubRequiresSecret(t *testing.T) {
	unsetSecret(t)

	_, err := ExtractSub("token")
	require.ErrorIs(t, err, terrors.TErrSecretKeyMissing)
}

func TestExtractSubRejectsInvalidToken(t *testing.T) {
	setSecret(t)

	_, err := ExtractSub("not-a-jwt")
	require.Error(t, err)
}

func TestExtractCustomClaims(t *testing.T) {
	setSecret(t)

	got, err := NewAccessToken("alice", "test-client", nil, `{"role":"admin"}`)
	require.NoError(t, err)

	claims, err := ExtractCustomClaims(got.Token)
	require.NoError(t, err)
	assert.Equal(t, `{"role":"admin"}`, claims)
}

func TestExtractCustomClaimsMissingClaim(t *testing.T) {
	setSecret(t)

	got, err := NewAccessToken("alice", "test-client", nil, "")
	require.NoError(t, err)

	claims, err := ExtractCustomClaims(got.Token)
	require.NoError(t, err)
	assert.Empty(t, claims)
}

func TestExtractCustomClaimsRequiresSecret(t *testing.T) {
	unsetSecret(t)

	_, err := ExtractCustomClaims("token")
	require.ErrorIs(t, err, terrors.TErrSecretKeyMissing)
}
