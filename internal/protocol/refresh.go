// Wire messages of the token-refresh flow across RP, Broker and IdP.
package protocol

// RefreshTokenFromRPRequest triggers a refresh. The broker holds the
// refresh_token, so the RP supplies identifiers only.
type RefreshTokenFromRPRequest struct {
	TID   string `json:"tid"`
	UIDRP string `json:"uid_rp"`
}

// RefreshTokenFromBrokerRequest carries the ratchet header (the RP DH public key
// at index seq) and the refresh_token from the broker to the IdP.
type RefreshTokenFromBrokerRequest struct {
	Hdr          []byte `json:"hdr"`
	Seq          uint32 `json:"seq"`
	RefreshToken string `json:"refresh_token"`
}

// RefreshTokenToRPResponse is relayed to the RP, which derives the message key
// from (hdr, seq) and decrypts c into the new access token.
type RefreshTokenToRPResponse struct {
	Hdr []byte `json:"hdr"`
	Seq uint32 `json:"seq"`
	C   []byte `json:"c"`
}
