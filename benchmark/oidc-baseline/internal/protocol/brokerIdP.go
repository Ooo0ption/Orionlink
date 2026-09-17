package protocol

import "secure-sso/lib"

type AAKETokenRequest struct {
	Sigma1 *lib.PSSignMsg `json:"sigma1"`
	Sigma2 *lib.PSSignMsg `json:"sigma2"`
	C      CGroup         `json:"c"`
	R      RGroup         `json:"r"`
	Z      ZGroup         `json:"z"`
	E2EE   E2EE           `json:"e2ee"`
	Code   string         `json:"code"`
}

type AAKETokenResponse struct {
	AUID         string `json:"auid"`
	IdToken      string `json:"id_token"`
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
}
