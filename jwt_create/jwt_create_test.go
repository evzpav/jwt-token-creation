package jwtcreate_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	jwt "github.com/dgrijalva/jwt-go"
	jwtcreate "github.com/evzpav/jwt-token-creation/jwt_create"
)

var publicKeyStr = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyRAKUXU5XLKmu9NpGGLX
R0BoUjGSOCOdPP3B4V6AOnsEEWZqygfivI4F95qKtF71nq4N/K38nF+3Ifc372MC
yzTRcxQpB6ZIM/oENbJ0oaFqbEFaVdm1WQmOyiXXq7luf2DxKirkq+hZPTv73+O0
3LPSSVfdRQPBuRU42Q+t5RG/m/k7GE8JGZNoL7to00BgoELDuDPZAprgRmm26fMG
i9gZxGl9FJYcMd0kLsoVtcNf7iHweZc8gwaEd20I63rkduvOsXt4IwvwbxKppkDQ
89xqwX39d7k0F+1Y5GShLMYkUHdqf401d3kiQTnLxorKed5Ds5vcLihDrZA+GoxC
9QIDAQAB
-----END PUBLIC KEY-----
`

var publicKeyPath = "../key.pub.pem"
var privateKeyPath = "../key"

func TestGetToken(t *testing.T) {
	t.Run("succesfully", func(t *testing.T) {
		token, err := jwtcreate.GetToken("Bearer token")
		assert.Nil(t, err)
		assert.Equal(t, "token", token)
	})

	t.Run("should return error if no space on authorization header", func(t *testing.T) {
		token, err := jwtcreate.GetToken("Bearertoken")
		assert.Error(t, err)
		assert.Equal(t, "", token)
	})

	t.Run("should return error if no Bearer prefix on authorization header", func(t *testing.T) {
		token, err := jwtcreate.GetToken("token")
		assert.Error(t, err)
		assert.Equal(t, "", token)
	})

	t.Run("should return error if empty string", func(t *testing.T) {
		token, err := jwtcreate.GetToken("")
		assert.Error(t, err)
		assert.Equal(t, "", token)
	})
}

func TestParseKeyPair(t *testing.T) {
	t.Run("succesfully public key", func(t *testing.T) {
		publickKey, err := jwtcreate.ParsePublicKey(publicKeyStr)
		assert.Nil(t, err)
		assert.NotNil(t, publickKey)
	})
}

func TestParseKeyPairFromFile(t *testing.T) {
	t.Run("succesfully public key", func(t *testing.T) {
		publickKey, err := jwtcreate.ParsePublicKeyFromFile(publicKeyPath)
		assert.Nil(t, err)
		assert.NotNil(t, publickKey)
	})

	t.Run("succesfully private key", func(t *testing.T) {
		publickKey, err := jwtcreate.ParsePrivateKeyFromFile(privateKeyPath)
		assert.Nil(t, err)
		assert.NotNil(t, publickKey)
	})
}

func TestDecode(t *testing.T) {
	clientID := "fake-client-id"
	clientApplicationID := "fake-application-id"
	clientApplicationName := "Fake Application"
	scopes := []string{"packages", "configs"}

	t.Run("succesfully", func(t *testing.T) {

		jwtToken, iat, expires, err := jwtcreate.GenerateJwtToken(clientID, clientApplicationID, clientApplicationName, scopes, 5)
		assert.Nil(t, err)

		accessToken := jwtcreate.AccessToken{PublicKey: iat.PublicKey}

		token, err := accessToken.Decode(jwtToken)
		assert.Nil(t, err)

		claims, ok := token.Claims.(*jwtcreate.Claims)
		assert.Equal(t, ok, true)
		assert.Equal(t, token.Valid, true)

		expected := &jwtcreate.Claims{
			StandardClaims: jwt.StandardClaims{
				Audience:  iat.Audience,
				ExpiresAt: expires,
				Issuer:    iat.Issuer,
				Subject:   clientApplicationID,
			},
			ClientID:              clientID,
			Scopes:                scopes,
			ClientApplicationName: clientApplicationName,
		}

		assert.Equal(t, expected, claims)
	})

	t.Run("should return error when token is invalid", func(t *testing.T) {
		pubKey, err := jwtcreate.ParsePublicKey(publicKeyStr)
		assert.Nil(t, err)
		accessToken := jwtcreate.NewAccessToken(pubKey)

		token, err := accessToken.Decode("invalidToken")
		assert.Errorf(t, err, "token contains an invalid number of segments")
		assert.Nil(t, token)

	})

}
