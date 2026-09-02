package memory

import (
	"errors"
	"sync"

	"github.com/atomicswe/tauth/internal/tokens"
)

var (
	ErrTokensNotFound = errors.New("the user does not have any stored tokens")
)

var Live = NewMemory()

type Memory struct {
	mu     sync.Mutex
	tokens map[string]tokens.TTokens
}

func NewMemory() *Memory {
	return &Memory{
		tokens: make(map[string]tokens.TTokens),
	}
}

func (m *Memory) Put(user string, tokens tokens.TTokens) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens[user] = tokens
}

func (m *Memory) Get(user string) (tokens.TTokens, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	stored, found := m.tokens[user]
	if !found {
		return tokens.TTokens{}, ErrTokensNotFound
	}
	return stored, nil
}

func (m *Memory) Remove(user string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	_, found := m.tokens[user]
	if !found {
		return ErrTokensNotFound
	}
	delete(m.tokens, user)
	return nil
}
