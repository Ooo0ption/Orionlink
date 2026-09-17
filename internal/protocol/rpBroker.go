// Wire messages of the RP to Broker exchanges: registration, PoK generation,
// AUID unblinding and code redemption.
package protocol

// RPRegisterToBrokerRequest is the Phase-1 RP to Broker register message, paper's
// (cid, DC), plus the scopes, callback URL and refresh-ratchet public keys the
// implementation needs.
type RPRegisterToBrokerRequest struct {
	Domain      []byte   `json:"domain"`
	Sig1        []byte   `json:"sig1"`
	Scopes      []string `json:"scopes"`
	CallbackURL string   `json:"callbackURL"`
	RPDHPks     [][]byte `json:"rp_dh_pks,omitempty"`
}

// RPRegisterToBrokerResponse returns TID, the broker's local handle for the
// registered RP, later carried in /ssso/authorize?tid=...
type RPRegisterToBrokerResponse struct {
	TID string `json:"tid"`
}

// AAKEGenPoKRequest is the Phase-2 broker to RP request for M. The broker passes
// in the per-session randomization scalars it already computed (RSig1 = sigma_1',
// T = t_1) along with the RP's OIDC state for callback correlation.
type AAKEGenPoKRequest struct {
	RSig1 []byte `json:"rSig1"`
	T     []byte `json:"t"`
	State string `json:"state"`
}

// CGroup holds the NIZK commitments C1, C2, C3.
type CGroup struct {
	C1 []byte `json:"c1"`
	C2 []byte `json:"c2"`
	C3 []byte `json:"c3"`
}

// RGroup holds the NIZK challenge announcements R1, R2, R3.
type RGroup struct {
	R1 []byte `json:"r1"`
	R2 []byte `json:"r2"`
	R3 []byte `json:"r3"`
}

// ZGroup holds the NIZK responses: zD and zQsk for the domain and identity
// secrets, z1 to z3 for the randomization scalars.
type ZGroup struct {
	ZD   []byte `json:"zd"`
	ZQsk []byte `json:"zqsk"`
	Z1   []byte `json:"z1"`
	Z2   []byte `json:"z2"`
	Z3   []byte `json:"z3"`
}

// E2EE is the X3DH half of M: the RP's identity and ephemeral public keys, the
// id of the IdP ephemeral key used, and the key-confirmation ciphertext.
type E2EE struct {
	ClientPK    []byte `json:"clientPk"`
	ClientEmpPK []byte `json:"clientEmpKey"`
	IdPEmpKeyId string `json:"idpEmpKeyId"`
	Msg         []byte `json:"msg"`
}

// AAKEGenPoKResponse is the RP's filled-in M, which the broker forwards wholesale
// into AAKETokenRequest: the randomized DC and SC signatures (Sign1 = acid,
// Sign2 = sigma_bar'), the NIZK pi_2 as C/R/Z, and the E2EE material. Sign1 and
// Sign2 are flat PSSignMsg.ToJSON() bytes.
type AAKEGenPoKResponse struct {
	Sign1 []byte `json:"sign1"`
	Sign2 []byte `json:"sign2"`
	C     CGroup `json:"c"`
	R     RGroup `json:"r"`
	Z     ZGroup `json:"z"`
	E2EE  E2EE   `json:"e2ee"`
}

// AAKETokenFromRPRequest is the RP to Broker code redemption after the callback,
// in the standard OAuth-2 authorization_code shape.
type AAKETokenFromRPRequest struct {
	GrantType string `json:"grant_type"`
	Code      string `json:"code"`
}

// UnblindAuidRequest carries the blinded AUID and the broker's per-session factor
// k to the RP, which performs the unblind itself (paper Fig.6 Phase 4).
type UnblindAuidRequest struct {
	AUID string `json:"auid"`
	K    []byte `json:"k"`
}

// UnblindAuidResponse returns the recovered per-(RP,user) pseudonym uid_rp, which
// the broker stores for routing.
type UnblindAuidResponse struct {
	UIDRP string `json:"uid_rp"`
}

// AAKETokenToRPResponse is the broker's reply at the code-exchange step. UIDRP is
// the per-(RP,user) pseudonym; the broker may hold it because the OPRF
// construction prevents linking uid_RP values across RPs to one global uid.
type AAKETokenToRPResponse struct {
	UIDRP       string `json:"uid_rp"`
	IdToken     string `json:"id_token"`
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
}
