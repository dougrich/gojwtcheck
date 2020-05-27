package gojwtcheck

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
	"testing"
	"errors"
)

func TestJWTParser(t *testing.T) {

	const (
		TestKID      = "test-key-identifier"
		TestUserID   = "test-user-id"
		TestUserName = "test-user-name"
	)

	createJWTPublic := func(kid string) (string, []byte) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		x509bytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			panic(err)
		}
		pempublickey := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: x509bytes,
		})
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"sub":  TestUserID,
			"name": TestUserName,
		})
		token.Header["kid"] = kid
		tokenString, err := token.SignedString(key)
		if err != nil {
			panic(err)
		}
		return tokenString, pempublickey
	}

	t.Run("OK", func(t *testing.T) {
		// create a test key
		assert := assert.New(t)
		token, publickey := createJWTPublic(TestKID)
		certstore := NewMockKeyStore(t)
		certstore.Value = publickey
		verifier := NewDefaultJWTParser(certstore)
		claims := jwt.MapClaims{}
		err := verifier.Check(context.Background(), token, &claims)
		assert.Nil(err)
		assert.Equal(claims["sub"], TestUserID)
		assert.Equal(claims["name"], TestUserName)
		certstore.ExpectWasCalledWith([]string{TestKID})
	})

	t.Run("ExceptionKID", func(t *testing.T) {
		// create a test key
		assert := assert.New(t)
		kid := TestKID + "-bad"
		token, _ := createJWTPublic(kid)
		certstore := NewMockKeyStore(t)
		certstore.Err = errors.New("internal kid error")
		verifier := NewDefaultJWTParser(certstore)
		claims := jwt.MapClaims{}
		err := verifier.Check(context.Background(), token, &claims)
		assert.EqualError(err, "Error occured attempting to fetch key to verify JWT: internal kid error")
		certstore.ExpectWasCalledWith([]string{kid})
	})

	t.Run("UnsupportedKID", func(t *testing.T) {
		// create a test key
		assert := assert.New(t)
		kid := TestKID + "-bad"
		token, _ := createJWTPublic(kid)
		certstore := NewMockKeyStore(t)
		certstore.Err = ErrorKeyNotFound
		verifier := NewDefaultJWTParser(certstore)
		claims := jwt.MapClaims{}
		err := verifier.Check(context.Background(), token, &claims)
		assert.EqualError(err, "KID not found")
		certstore.ExpectWasCalledWith([]string{kid})
	})

	t.Run("BadToken", func(t *testing.T) {
		// create a test key
		assert := assert.New(t)
		certstore := NewMockKeyStore(t)
		certstore.Err = ErrorKeyNotFound
		verifier := NewDefaultJWTParser(certstore)
		claims := jwt.MapClaims{}
		err := verifier.Check(context.Background(), "", &claims)
		assert.EqualError(err, "token contains an invalid number of segments")
		certstore.ExpectWasCalledWith([]string{})
	})
}
