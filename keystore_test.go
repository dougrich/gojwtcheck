package gojwtcheck

import (
	"testing"
	"context"
	"crypto/rsa"
)

// Mock

type MockKeyStore struct {
	t *testing.T
	Public *rsa.PublicKey
	Kid string
	Private *rsa.PrivateKey
	Err error
	calls []string
}

func (m *MockKeyStore) Reset(t *testing.T) {
	m.t = t
	m.Public = nil
	m.Private = nil
	m.Kid = ""
	m.Err = nil
	m.calls = []string{}
}

func (m *MockKeyStore) ExpectWasCalledWith(calls []string) {
	actualLen := len(m.calls)
	expectedLen := len(calls)
	if actualLen != expectedLen {
		m.t.Errorf("MockKeyStore expected to have been called %d times; was actually called %d times", expectedLen, actualLen)
		return
	}

	for i, expected := range calls {
		actual := m.calls[i]
		if actual != expected {
			m.t.Errorf("MockKeyStore expected call %d to be '%s'; was actually '%s'", i, expected, actual)
		}
	}
}

func (m *MockKeyStore) FetchRSA(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	m.calls = append(m.calls, kid)
	return m.Public, m.Err
}
func (m *MockKeyStore) FetchRSASigningKey(ctx context.Context) (*rsa.PrivateKey, string, error) {
	return m.Private, m.Kid, nil
}

func NewMockKeyStore(t *testing.T) *MockKeyStore {
	m := &MockKeyStore{}
	m.Reset(t)
	return m
}