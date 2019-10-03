package main

import (
	"fmt"
	"log"

	jwtcreate "github.com/evzpav/jwt-token-creation/jwt_create"
)

func main() {
	clientID := "client-id"
	clientApplicationID := "application-id"
	clientApplicationName := "My Application"
	scopes := []string{"configs", "packages"}

	privKey, err := jwtcreate.ParsePrivateKeyFromFile("./key")
	if err != nil {
		log.Fatalf("could not parse private key: %+v", err)
	}

	expireInMin := 5
	jwtToken, _, _, err := jwtcreate.GenerateJwtTokenCustom(clientID, clientApplicationID, clientApplicationName, scopes, privKey, expireInMin)
	if err != nil {
		log.Fatalf("could not generate token: %+v", err)
	}
	fmt.Printf("JWT TOKEN: \n%s \n\n", jwtToken)

	pubKey, err := jwtcreate.ParsePublicKeyFromFile("./key.pub.pem")
	if err != nil {
		log.Fatalf("could not parse public key: %+v", err)
	}

	accessToken := jwtcreate.NewAccessToken(pubKey)
	token, err := accessToken.Decode(jwtToken)
	if err != nil {
		log.Fatalf("could not decode token: %+v", err)
	}

	claims, ok := token.Claims.(*jwtcreate.Claims)
	if !ok && token.Valid {
		log.Fatalf("invalid token")
	}
	fmt.Printf("CLAIMS: \n%+v \n", claims)
}
