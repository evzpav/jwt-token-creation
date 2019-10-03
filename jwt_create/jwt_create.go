package jwtcreate

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

type AccessToken struct {
	Audience   string
	Issuer     string
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

type Claims struct {
	jwt.StandardClaims
	ClientID              string   `json:"cid"`
	ClientApplicationName string   `json:"can"`
	Scopes                []string `json:"scopes"`
}

func NewAccessToken(pubKey *rsa.PublicKey) *AccessToken {
	return &AccessToken{
		PublicKey: pubKey,
	}
}

func (at *AccessToken) Decode(token string) (*jwt.Token, error) {
	return jwt.ParseWithClaims(token, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method error: %v", t.Header["alg"])
		}
		return at.PublicKey, nil
	})
}

func (at *AccessToken) Encode(
	clientID string,
	clientApplicationID string,
	clientApplicationName string,
	scopes []string,
	expires int64,
) (string, error) {
	c := Claims{
		StandardClaims: jwt.StandardClaims{
			Audience:  at.Audience,
			ExpiresAt: expires,
			Issuer:    at.Issuer,
			Subject:   clientApplicationID,
		},
		ClientID:              clientID,
		Scopes:                scopes,
		ClientApplicationName: clientApplicationName,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, c)

	return token.SignedString(at.PrivateKey)

}

func ParsePublicKey(key string) (*rsa.PublicKey, error) {
	return jwt.ParseRSAPublicKeyFromPEM([]byte(key))
}

func ParsePrivateKey(key string) (*rsa.PrivateKey, error) {
	return jwt.ParseRSAPrivateKeyFromPEM([]byte(key))
}

func ParsePublicKeyFromFile(publicKeyFile string) (*rsa.PublicKey, error) {
	publicKeyContent, err := readFile(publicKeyFile)
	if err != nil {
		return nil, err
	}
	return ParsePublicKey(string(publicKeyContent))
}

func ParsePrivateKeyFromFile(privateKeyFile string) (*rsa.PrivateKey, error) {
	keyContent, err := readFile(privateKeyFile)
	if err != nil {
		return nil, err
	}

	return ParsePrivateKey(string(keyContent))
}

func GetToken(authorizationHeader string) (string, error) {
	if authorizationHeader == "" {
		return "", fmt.Errorf("authorization failed")
	}

	token := strings.SplitN(authorizationHeader, " ", 2)
	if len(token) != 2 || token[0] != "Bearer" {
		return "", fmt.Errorf("authorization failed")
	}

	return token[1], nil
}

func readFile(keyPath string) ([]byte, error) {
	return ioutil.ReadFile(filepath.Clean(keyPath))
}

func GenerateJwtToken(clientID, clientApplicationID, clientApplicationName string, scopes []string, expireMin int) (string, *AccessToken, int64, error) {

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", nil, 0, fmt.Errorf("unexpected error generating key pair: %v", err)
	}

	return GenerateJwtTokenCustom(clientID, clientApplicationID, clientApplicationName, scopes, key, expireMin)

}

func GenerateJwtTokenCustom(clientID, clientApplicationID, clientApplicationName string, scopes []string, key *rsa.PrivateKey, expireMin int) (string, *AccessToken, int64, error) {

	expires := time.Now().Add(time.Duration(expireMin) * time.Minute).UTC().Unix()

	at := &AccessToken{
		Audience:   "aud",
		Issuer:     "iss",
		PrivateKey: key,
		PublicKey:  &key.PublicKey,
	}

	token, err := at.Encode(
		clientID,
		clientApplicationID,
		clientApplicationName,
		scopes,
		expires,
	)

	if err != nil {
		return "", nil, 0, fmt.Errorf("unexpected generating token error: %v", err)
	}
	return token, at, expires, nil
}
