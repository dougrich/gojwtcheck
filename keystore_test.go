package gojwtcheck

import (
	"testing"
	"context"
)

// Mock

type MockKeyStore struct {
	t *testing.T
	Value []byte
	Err error
	calls []string
}

func (m *MockKeyStore) Reset(t *testing.T) {
	m.t = t
	m.Value = nil
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

func (m *MockKeyStore) FetchRSA(ctx context.Context, kid string) ([]byte, error) {
	m.calls = append(m.calls, kid)
	return m.Value, m.Err
}

func NewMockKeyStore(t *testing.T) *MockKeyStore {
	m := &MockKeyStore{}
	m.Reset(t)
	return m
}