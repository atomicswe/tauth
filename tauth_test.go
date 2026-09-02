package tauth_test

import (
	"os"
	"testing"
	"time"

	"github.com/atomicswe/tauth"
	"github.com/atomicswe/tauth/internal/common"
	"github.com/atomicswe/tauth/internal/memory"
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

func durationPtr(d time.Duration) *time.Duration {
	return &d
}

func validOptions() tauth.TAuthOptions {
	return tauth.TAuthOptions{
		Sub:          "test-client",
		ATExpiration: durationPtr(15 * time.Minute),
		RTExpiration: durationPtr(2 * time.Hour),
		CustomClaims: `{"role":"admin"}`,
	}
}

func TestIssueTokensSucceeds(t *testing.T) {
	setSecret(t)

	user := t.Name()
	issued, err := tauth.IssueTokens(user, validOptions())
	require.NoError(t, err)

	assert.NotEmpty(t, issued.AccessToken.Token)
	assert.NotEmpty(t, issued.RefreshToken.Token)
	assert.Equal(t, 15*time.Minute, issued.AccessToken.Expiration)
	assert.Equal(t, 2*time.Hour, issued.RefreshToken.Expiration)
	assert.True(t, issued.AccessToken.ExpiresAt.After(time.Now()))
	assert.True(t, issued.RefreshToken.ExpiresAt.After(time.Now()))
	assert.Len(t, issued.RefreshToken.Token, 32)

	gotUser, customClaims, err := tauth.ValidateToken(issued.AccessToken.Token)
	require.NoError(t, err)
	assert.Equal(t, user, gotUser)
	assert.JSONEq(t, `{"role":"admin"}`, customClaims)

	cached, err := memory.Live.Get(user)
	require.NoError(t, err)
	assert.Equal(t, issued, cached)
}

func TestIssueTokensUsesDefaultsWhenExpirationsOmitted(t *testing.T) {
	setSecret(t)

	issued, err := tauth.IssueTokens(t.Name(), tauth.TAuthOptions{Sub: "test-client"})
	require.NoError(t, err)
	assert.Equal(t, 5*time.Minute, issued.AccessToken.Expiration)
	assert.Equal(t, 24*time.Hour, issued.RefreshToken.Expiration)
}

func TestIssueTokensTrimsUser(t *testing.T) {
	setSecret(t)

	user := t.Name()
	issued, err := tauth.IssueTokens("  "+user+"  ", validOptions())
	require.NoError(t, err)

	gotUser, _, err := tauth.ValidateToken(issued.AccessToken.Token)
	require.NoError(t, err)
	assert.Equal(t, user, gotUser)

	_, err = memory.Live.Get(user)
	require.NoError(t, err)
}

func TestIssueTokensAllowsMinimumExpirations(t *testing.T) {
	setSecret(t)

	issued, err := tauth.IssueTokens(t.Name(), tauth.TAuthOptions{
		Sub:          "test-client",
		ATExpiration: durationPtr(5 * time.Minute),
		RTExpiration: durationPtr(time.Hour),
	})
	require.NoError(t, err)
	assert.Equal(t, 5*time.Minute, issued.AccessToken.Expiration)
	assert.Equal(t, time.Hour, issued.RefreshToken.Expiration)
}

func TestIssueTokensValidationErrors(t *testing.T) {
	tests := []struct {
		name string
		user string
		opts tauth.TAuthOptions
		want error
	}{
		{
			name: "empty user",
			user: "",
			opts: tauth.TAuthOptions{Sub: "test-client"},
			want: terrors.TErrUserRequired,
		},
		{
			name: "whitespace user",
			user: "   ",
			opts: tauth.TAuthOptions{Sub: "test-client"},
			want: terrors.TErrUserRequired,
		},
		{
			name: "empty sub",
			user: "user",
			opts: tauth.TAuthOptions{},
			want: terrors.TErrSubRequired,
		},
		{
			name: "whitespace sub",
			user: "user",
			opts: tauth.TAuthOptions{Sub: "   "},
			want: terrors.TErrSubRequired,
		},
		{
			name: "access token expiration too low",
			user: "user",
			opts: tauth.TAuthOptions{
				Sub:          "test-client",
				ATExpiration: durationPtr(time.Minute),
			},
			want: terrors.TErrRTExpTooLow,
		},
		{
			name: "refresh token expiration too low",
			user: "user",
			opts: tauth.TAuthOptions{
				Sub:          "test-client",
				RTExpiration: durationPtr(time.Minute),
			},
			want: terrors.TErrRTExpTooLow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tauth.IssueTokens(tt.user, tt.opts)
			require.ErrorIs(t, err, tt.want)
		})
	}
}

func TestIssueTokensRequiresSecret(t *testing.T) {
	unsetSecret(t)

	_, err := tauth.IssueTokens(t.Name(), validOptions())
	require.ErrorIs(t, err, terrors.TErrSecretKeyMissing)
}

func TestValidateTokenSucceedsWithoutCustomClaims(t *testing.T) {
	setSecret(t)

	user := t.Name()
	issued, err := tauth.IssueTokens(user, tauth.TAuthOptions{Sub: "test-client"})
	require.NoError(t, err)

	gotUser, customClaims, err := tauth.ValidateToken(issued.AccessToken.Token)
	require.NoError(t, err)
	assert.Equal(t, user, gotUser)
	assert.Empty(t, customClaims)
}

func TestValidateTokenRequiresSecret(t *testing.T) {
	unsetSecret(t)

	_, _, err := tauth.ValidateToken("token")
	require.ErrorIs(t, err, terrors.TErrSecretKeyMissing)
}

func TestValidateTokenRejectsRefreshToken(t *testing.T) {
	setSecret(t)

	issued, err := tauth.IssueTokens(t.Name(), validOptions())
	require.NoError(t, err)

	_, _, err = tauth.ValidateToken(issued.RefreshToken.Token)
	require.Error(t, err)
}

func TestValidateTokenRejectsMalformedToken(t *testing.T) {
	setSecret(t)

	_, _, err := tauth.ValidateToken("not-a-jwt")
	require.Error(t, err)
}

func TestValidateTokenRejectsWrongSecret(t *testing.T) {
	setSecret(t)

	issued, err := tauth.IssueTokens(t.Name(), validOptions())
	require.NoError(t, err)

	t.Setenv("TAUTH_SECRET_KEY", "other-secret")
	_, _, err = tauth.ValidateToken(issued.AccessToken.Token)
	require.Error(t, err)
}

func TestValidateTokenHonorsCustomIssuer(t *testing.T) {
	setSecret(t)
	t.Setenv("TAUTH_ISS", "custom-issuer")

	issued, err := tauth.IssueTokens(t.Name(), validOptions())
	require.NoError(t, err)

	_, _, err = tauth.ValidateToken(issued.AccessToken.Token)
	require.NoError(t, err)
}

func TestValidateTokenRejectsWrongIssuer(t *testing.T) {
	setSecret(t)

	issued, err := tauth.IssueTokens(t.Name(), validOptions())
	require.NoError(t, err)

	t.Setenv("TAUTH_ISS", "other-issuer")
	_, _, err = tauth.ValidateToken(issued.AccessToken.Token)
	require.Error(t, err)
}

func TestValidateTokenRejectsExpiredToken(t *testing.T) {
	setSecret(t)

	token := mustSign(t, jwt.MapClaims{
		"iss":  common.DefaultIssuer,
		"exp":  time.Now().Add(-2 * time.Minute).Unix(),
		"sub":  "test-client",
		"user": t.Name(),
	})

	_, _, err := tauth.ValidateToken(token)
	require.Error(t, err)
}

func TestValidateTokenRejectsMissingExpiration(t *testing.T) {
	setSecret(t)

	token := mustSign(t, jwt.MapClaims{
		"iss":  common.DefaultIssuer,
		"sub":  "test-client",
		"user": t.Name(),
	})

	_, _, err := tauth.ValidateToken(token)
	require.Error(t, err)
}

func TestValidateTokenRejectsWrongSigningMethod(t *testing.T) {
	setSecret(t)

	token, err := jwt.NewWithClaims(jwt.SigningMethodHS384, jwt.MapClaims{
		"iss":  common.DefaultIssuer,
		"exp":  time.Now().Add(time.Minute).Unix(),
		"sub":  "test-client",
		"user": t.Name(),
	}).SignedString([]byte(testSecret))
	require.NoError(t, err)

	_, _, err = tauth.ValidateToken(token)
	require.Error(t, err)
}

func TestRefreshTokensSucceeds(t *testing.T) {
	setSecret(t)

	user := t.Name()
	oldTokens, err := tauth.IssueTokens(user, validOptions())
	require.NoError(t, err)

	newTokens, err := tauth.RefreshTokens(user, oldTokens.RefreshToken.Token)
	require.NoError(t, err)

	assert.NotEmpty(t, newTokens.AccessToken.Token)
	assert.NotEmpty(t, newTokens.RefreshToken.Token)
	assert.NotEqual(t, oldTokens.AccessToken.Token, newTokens.AccessToken.Token)
	assert.NotEqual(t, oldTokens.RefreshToken.Token, newTokens.RefreshToken.Token)
	assert.Equal(t, oldTokens.AccessToken.Expiration, newTokens.AccessToken.Expiration)
	assert.Equal(t, oldTokens.RefreshToken.Expiration, newTokens.RefreshToken.Expiration)

	gotUser, customClaims, err := tauth.ValidateToken(newTokens.AccessToken.Token)
	require.NoError(t, err)
	assert.Equal(t, user, gotUser)
	assert.JSONEq(t, `{"role":"admin"}`, customClaims)

	_, _, err = tauth.ValidateToken(oldTokens.AccessToken.Token)
	require.NoError(t, err)

	cached, err := memory.Live.Get(user)
	require.NoError(t, err)
	assert.Equal(t, newTokens, cached)
}

func TestRefreshTokensSucceedsWithoutCustomClaims(t *testing.T) {
	setSecret(t)

	user := t.Name()
	oldTokens, err := tauth.IssueTokens(user, tauth.TAuthOptions{Sub: "test-client"})
	require.NoError(t, err)

	newTokens, err := tauth.RefreshTokens(user, oldTokens.RefreshToken.Token)
	require.NoError(t, err)

	gotUser, customClaims, err := tauth.ValidateToken(newTokens.AccessToken.Token)
	require.NoError(t, err)
	assert.Equal(t, user, gotUser)
	assert.Empty(t, customClaims)
}

func TestRefreshTokensValidationErrors(t *testing.T) {
	setSecret(t)

	t.Run("empty user", func(t *testing.T) {
		_, err := tauth.RefreshTokens("", "token")
		require.ErrorIs(t, err, terrors.TErrUserRequired)
	})

	t.Run("whitespace user", func(t *testing.T) {
		_, err := tauth.RefreshTokens("   ", "token")
		require.ErrorIs(t, err, terrors.TErrUserRequired)
	})

	t.Run("tokens not found", func(t *testing.T) {
		_, err := tauth.RefreshTokens(t.Name(), "token")
		require.ErrorIs(t, err, terrors.TErrTokensNotFound)
	})

	t.Run("refresh token mismatch", func(t *testing.T) {
		user := t.Name()
		_, err := tauth.IssueTokens(user, validOptions())
		require.NoError(t, err)

		_, err = tauth.RefreshTokens(user, "not-the-stored-token")
		require.ErrorIs(t, err, terrors.TErrRefreshTokenMismatch)
	})

	t.Run("refresh token expired", func(t *testing.T) {
		user := t.Name()
		issued, err := tauth.IssueTokens(user, validOptions())
		require.NoError(t, err)

		issued.RefreshToken.ExpiresAt = time.Now().Add(-time.Second)
		memory.Live.Put(user, issued)

		_, err = tauth.RefreshTokens(user, issued.RefreshToken.Token)
		require.ErrorIs(t, err, terrors.TErrRefreshTokenExpired)
	})
}

func mustSign(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(testSecret))
	require.NoError(t, err)
	return token
}
