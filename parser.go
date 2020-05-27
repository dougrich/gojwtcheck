package gojwtcheck

import (
	"context"
	"github.com/dgrijalva/jwt-go"
	"errors"
)

const (
	ErrorJWTMissingAlgorithm             = "JWT Token missing algorithm"
	ErrorJWTUnsupportedAlgorithm         = "JWT Token contains unsupported algorithm"
	ErrorJWTMissingKeyIdentifier         = "JWT Token missing Key Identifier (kid)"
	ErrorJWTUnsupportedKeyIdentifierType = "JWT Token Key Identifier is an unsupported type; only strings are valid"
	ErrorJWTCertificateFetch             = "Error occured attempting to fetch key to verify JWT"
	ErrorJWTCertificateParse             = "Error occured attempting to parse key to verify JWT"
	ErrorJWTValidation                   = "Error occured attempting to validate JWT token"
)

type JWTParser interface {
	Check(ctx context.Context, token string, claims jwt.Claims) error
}

type DefaultJWTParser struct {
	keys KeyStore
}

func NewDefaultJWTParser(keys KeyStore) *DefaultJWTParser {
	return &DefaultJWTParser{
		keys,
	}
}

func (p *DefaultJWTParser) Check(ctx context.Context, token string, claims jwt.Claims) error {
	_, err := jwt.ParseWithClaims(token, claims, func (token *jwt.Token) (interface{}, error) {
		alg, ok := token.Header["alg"]
		if !ok {
			return nil, errors.New(ErrorJWTMissingAlgorithm)
		}
		isValidAlgorithm := false
		for _, s := range []string{"RS256", "RS384", "RS512"} {
			isValidAlgorithm = isValidAlgorithm || alg == s
		}
		if !isValidAlgorithm {
			return nil, errors.New(ErrorJWTUnsupportedAlgorithm)
		}
		kid, ok := token.Header["kid"]
		if !ok {
			return nil, errors.New(ErrorJWTMissingKeyIdentifier)
		}

		kidstr, ok := kid.(string)
		if !ok {
			return nil, errors.New(ErrorJWTUnsupportedKeyIdentifierType)
		}
		key, err := p.keys.FetchRSA(ctx, kidstr)
		if err == ErrorKeyNotFound {
			return nil, err
		} else if err != nil {
			return nil, NestedError{ErrorJWTCertificateFetch, err}
		}
		return key, nil
	})
	return err
}