package memory

import (
	"sync"

	"github.com/atomicswe/tauth/internal/tokens"
	"github.com/atomicswe/tauth/pkg/terrors"
)

var Live = NewMemory()

type Memory struct {
	mu     sync.Mutex
	tokens map[string]tokens.TTokens
}

// NewMemory creates an in-memory token store.
func NewMemory() *Memory {
	return &Memory{
		tokens: make(map[string]tokens.TTokens),
	}
}

// Put stores tokens for a user.
func (m *Memory) Put(user string, tokens tokens.TTokens) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens[user] = tokens
}

// Get retrieves stored tokens for a user.
func (m *Memory) Get(user string) (tokens.TTokens, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	stored, found := m.tokens[user]
	if !found {
		return tokens.TTokens{}, terrors.TErrTokensNotFound
	}
	return stored, nil
}

// Remove deletes stored tokens for a user.
func (m *Memory) Remove(user string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	_, found := m.tokens[user]
	if !found {
		return terrors.TErrTokensNotFound
	}
	delete(m.tokens, user)
	return nil
}
