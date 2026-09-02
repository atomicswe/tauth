package memory

import (
	"testing"
	"time"

	"github.com/atomicswe/tauth/internal/tokens"
	"github.com/atomicswe/tauth/pkg/terrors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sampleTokens(access, refresh string) tokens.TTokens {
	return tokens.TTokens{
		AccessToken: tokens.TAccessToken{
			Token:      access,
			Expiration: 15 * time.Minute,
			ExpiresAt:  time.Now().Add(15 * time.Minute),
		},
		RefreshToken: tokens.TRefreshToken{
			Token:      refresh,
			Expiration: 24 * time.Hour,
			ExpiresAt:  time.Now().Add(24 * time.Hour),
		},
	}
}

func TestMemoryPutGet(t *testing.T) {
	store := NewMemory()
	want := sampleTokens("access", "refresh")

	store.Put("alice", want)

	got, err := store.Get("alice")
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestMemoryGetMissing(t *testing.T) {
	store := NewMemory()

	_, err := store.Get("missing")
	require.ErrorIs(t, err, terrors.TErrTokensNotFound)
}

func TestMemoryPutOverwrites(t *testing.T) {
	store := NewMemory()
	store.Put("alice", sampleTokens("old-access", "old-refresh"))
	updated := sampleTokens("new-access", "new-refresh")
	store.Put("alice", updated)

	got, err := store.Get("alice")
	require.NoError(t, err)
	assert.Equal(t, updated, got)
}

func TestMemoryRemove(t *testing.T) {
	store := NewMemory()
	store.Put("alice", sampleTokens("access", "refresh"))

	require.NoError(t, store.Remove("alice"))

	_, err := store.Get("alice")
	require.ErrorIs(t, err, terrors.TErrTokensNotFound)
}

func TestMemoryRemoveMissing(t *testing.T) {
	store := NewMemory()

	err := store.Remove("missing")
	require.ErrorIs(t, err, terrors.TErrTokensNotFound)
}

func TestMemoryIsolatesUsers(t *testing.T) {
	store := NewMemory()
	alice := sampleTokens("alice-at", "alice-rt")
	bob := sampleTokens("bob-at", "bob-rt")
	store.Put("alice", alice)
	store.Put("bob", bob)

	gotAlice, err := store.Get("alice")
	require.NoError(t, err)
	assert.Equal(t, alice, gotAlice)

	gotBob, err := store.Get("bob")
	require.NoError(t, err)
	assert.Equal(t, bob, gotBob)

	require.NoError(t, store.Remove("alice"))
	_, err = store.Get("alice")
	require.ErrorIs(t, err, terrors.TErrTokensNotFound)

	gotBob, err = store.Get("bob")
	require.NoError(t, err)
	assert.Equal(t, bob, gotBob)
}
