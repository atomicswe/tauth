package tokens

import (
	"testing"
	"time"
	"unicode"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRefreshTokenSucceeds(t *testing.T) {
	exp := 48 * time.Hour
	before := time.Now()
	got, err := NewRefreshToken(&exp)
	require.NoError(t, err)

	assert.Len(t, got.Token, refreshtTokenSize)
	assert.Equal(t, exp, got.Expiration)
	assert.True(t, got.ExpiresAt.After(before))
	assert.True(t, got.ExpiresAt.Before(time.Now().Add(exp+time.Second)))

	for _, r := range got.Token {
		assert.True(t, unicode.IsLetter(r) || unicode.IsDigit(r), "unexpected char %q", r)
	}
}

func TestNewRefreshTokenUsesDefaultExpiration(t *testing.T) {
	got, err := NewRefreshToken(nil)
	require.NoError(t, err)
	assert.Equal(t, defaultRTExpiration, got.Expiration)
}

func TestNewRefreshTokenIsUnique(t *testing.T) {
	first, err := NewRefreshToken(nil)
	require.NoError(t, err)
	second, err := NewRefreshToken(nil)
	require.NoError(t, err)
	assert.NotEqual(t, first.Token, second.Token)
}
