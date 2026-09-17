package protocol

import (
	"secure-sso/lib"
)

type RPRegisterToBrokerRequest struct {
	Domain      []byte   `json:"domain"`
	Sig1        []byte   `json:"sig1"`
	Scopes      []string `json:"scopes"`
	CallbackURL string   `json:"callbackURL"`
	// RPDHPks carries a precomputed list of RP DH public keys for refresh-token ratchet.
	// Each element should be compressed G1 bytes.
	RPDHPks [][]byte `json:"rp_dh_pks,omitempty"`
}

type RPRegisterToBrokerResponse struct {
	TID string `json:"tid"`
}

type AAKEGenPoKRequest struct {
	RSig1 *lib.PSSignMsg `json:"rSig1"`
	T     []byte         `json:"t"`
	State string         `json:"state"`
}

type CGroup struct {
	C1 []byte `json:"c1"`
	C2 []byte `json:"c2"`
	C3 []byte `json:"c3"`
}

type RGroup struct {
	R1 []byte `json:"r1"`
	R2 []byte `json:"r2"`
	R3 []byte `json:"r3"`
}

type ZGroup struct {
	ZD   []byte `json:"zd"`
	ZQsk []byte `json:"zqsk"`
	Z1   []byte `json:"z1"`
	Z2   []byte `json:"z2"`
	Z3   []byte `json:"z3"`
}

type E2EE struct {
	ClientPK    []byte `json:"clientPk"`
	ClientEmpPK []byte `json:"clientEmpKey"`
	IdPEmpKeyId string `json:"idpEmpKeyId"`
	Msg         []byte `json:"msg"`
}
type AAKEGenPoKResponse struct {
	Sigma1 *lib.PSSignMsg `json:"sigma1"`
	Sigma2 *lib.PSSignMsg `json:"sigma2"`
	C      CGroup         `json:"c"`
	R      RGroup         `json:"r"`
	Z      ZGroup         `json:"z"`
	E2EE   E2EE           `json:"e2ee"`
}

type AAKETokenFromRPRequest struct {
	GrantType string `json:"grant_type"`
	Code      string `json:"code"`
}
type AAKETokenToRPResponse struct {
	UIDRP       string `json:"uid_rp"`
	IdToken     string `json:"id_token"`
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
}
