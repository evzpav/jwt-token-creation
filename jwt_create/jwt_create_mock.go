package jwtcreate

func NewMockAccessToken() (*AccessToken, string) {
	clientID := "fake-client-id"
	clientApplicationID := "fake-application-id"
	clientApplicationName := "Fake Application"
	scopes := []string{"packages", "configs"}
	jwtToken, iat, _, _ := GenerateJwtToken(clientID, clientApplicationID, clientApplicationName, scopes, 5)
	accessToken := &AccessToken{PublicKey: iat.PublicKey}
	return accessToken, jwtToken
}
