package protocol

// SecureSSO Refresh (RP <-> Broker <-> IdP)

// RefreshTokenFromRPRequest is sent from RP to Broker to trigger refresh.
// Broker is expected to hold the refresh_token (stored during /token exchange),
// so RP only provides identifiers.
type RefreshTokenFromRPRequest struct {
	TID   string `json:"tid"`    // RP identifier at Broker (same as registration TID)
	UIDRP string `json:"uid_rp"` // user id (unblinded AUID) used as index in Broker user store
}

// RefreshTokenFromBrokerRequest is sent from Broker to IdP.
// It carries the header (RP DH public key at index seq) and refresh_token.
type RefreshTokenFromBrokerRequest struct {
	Hdr          []byte `json:"hdr"`           // compressed G1 bytes (RP DH public key for this seq)
	Seq          uint32 `json:"seq"`           // which RP DH private key will be used on RP side
	RefreshToken string `json:"refresh_token"` // IdP-issued refresh token (JWT)
}

// RefreshTokenToRPResponse is relayed by Broker to RP.
// RP will use (hdr, seq) to derive message key and decrypt c to obtain new access_token.
type RefreshTokenToRPResponse struct {
	Hdr []byte `json:"hdr"` // compressed G1 bytes (IdP DH public key)
	Seq uint32 `json:"seq"`
	C   []byte `json:"c"` // ciphertext produced by IdP (AES-GCM: nonce||ciphertext)
}
