package gojwtcheck

import (
	"context"
	"github.com/dgrijalva/jwt-go"
)

type JWTAuthority interface {
	Sign(ctx context.Context, claims jwt.Claims) (string, error)
}

type DefaultJWTAuthority struct {
	keys KeyStore
}

func NewDefaultJWTAuthority(keys KeyStore) *DefaultJWTAuthority {
	return &DefaultJWTAuthority {
		keys,
	}
}

func (a *DefaultJWTAuthority) Sign(ctx context.Context, claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	key, kid, err := a.keys.FetchRSASigningKey(ctx)
	if err != nil {
		return "", err
	}
	token.Header["kid"] = kid
	ss, err := token.SignedString(key)
	return ss, err
}