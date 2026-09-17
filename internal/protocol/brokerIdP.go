// Wire messages of the Broker to IdP exchange.
package protocol

// AAKETokenRequest is the Phase-4 broker to IdP authentication request, paper's
// (acid, M, code): Sign1 carries acid, Sign2 plus the proof and E2EE fields carry
// M, and Code is the authorization code issued at consent time. Sign1 and Sign2
// are flat PSSignMsg.ToJSON() bytes, decoded with FromJSON.
type AAKETokenRequest struct {
	Sign1 []byte `json:"sign1"`
	Sign2 []byte `json:"sign2"`
	C     CGroup `json:"c"`
	R     RGroup `json:"r"`
	Z     ZGroup `json:"z"`
	E2EE  E2EE   `json:"e2ee"`
	Code  string `json:"code"`
}

// AAKETokenResponse is the Phase-4 IdP to broker response, paper's
// (auid, info_Enc) plus the JWT tokens brokered SSO needs. AUID is still blinded;
// the unblind to uid_RP happens afterwards with the broker's session-local k.
type AAKETokenResponse struct {
	AUID         string `json:"auid"`
	IdToken      string `json:"id_token"`
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
}
