package memory

import (
	"errors"
	"sync"

	"github.com/atomicswe/tauth"
)

var (
	ErrTokensNotFound = errors.New("the user does not have any stored tokens")
)

var Live = NewMemory()

type Memory struct {
	mu     sync.Mutex
	tokens map[string]tauth.TTokens
}

func NewMemory() *Memory {
	return &Memory{
		tokens: make(map[string]tauth.TTokens),
	}
}

func (m *Memory) Put(user string, tokens tauth.TTokens) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens[user] = tokens
}

func (m *Memory) Get(user string) (tauth.TTokens, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	tokens, found := m.tokens[user]
	if !found {
		return tauth.TTokens{}, ErrTokensNotFound
	}
	return tokens, nil
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
