package gojwtcheck

import (
	"context"
	"io/ioutil"
	"errors"
	"crypto/rsa"
	"github.com/dgrijalva/jwt-go"
)

var (
	ErrorKeyNotFound = errors.New("KID not found")
)

type KeyStore interface {
	FetchRSA(ctx context.Context, kid string) (*rsa.PublicKey, error)
	FetchRSASigningKey(ctx context.Context) (*rsa.PrivateKey, string, error)
}

type SingleKeyStore struct {
	kid string
	public *rsa.PublicKey
	private *rsa.PrivateKey
}

func NewSingleKeyStoreFromFile(kid string, publicfilename string, privatefilename string) (*SingleKeyStore, error) {
	publicdat, err := ioutil.ReadFile(publicfilename)
	if err != nil {
		return nil, err
	}
	publickey, err := jwt.ParseRSAPublicKeyFromPEM(publicdat)
	if err != nil {
		return nil, err
	}
	privatedat, err := ioutil.ReadFile(privatefilename)
	if err != nil {
		return nil, err
	}
	privatekey, err := jwt.ParseRSAPrivateKeyFromPEM(privatedat)
	if err != nil {
		return nil, err
	}
	return &SingleKeyStore{
		kid,
		publickey,
		privatekey,
	}, nil
}

func (ks *SingleKeyStore) FetchRSA(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	if kid != ks.kid {
		return nil, ErrorKeyNotFound
	}
	return ks.public, nil
}
func (ks *SingleKeyStore) FetchRSASigningKey(ctx context.Context) (*rsa.PrivateKey, string, error) {
	return ks.private, ks.kid, nil
}