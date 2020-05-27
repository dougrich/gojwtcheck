package gojwtcheck

import (
	"context"
	"io/ioutil"
	"errors"
)

var (
	ErrorKeyNotFound = errors.New("KID not found")
)

type KeyStore interface {
	FetchRSA(ctx context.Context, kid string) ([]byte, error)
}

type SingleKeyStore struct {
	kid string
	dat []byte
}

func NewSingleKeyStoreFromFile(kid string, filename string) (*SingleKeyStore, error) {
	dat, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return &SingleKeyStore{
		kid,
		dat,
	}, nil
}

func (ks *SingleKeyStore) FetchRSA(ctx context.Context, kid string) ([]byte, error) {
	if kid != ks.kid {
		return nil, ErrorKeyNotFound
	}
	return ks.dat, nil
}