package common

import (
	"secure-sso/lib"

	"github.com/cloudflare/circl/ecc/bls12381"
)

// 逻辑 ID
type RPID string      // RP 内部 ID
type BrokerID string  // Broker 自己的 ID
type UserID string    // IdP 的 uid
type SessionID string // 一次 SSO 授权会话
type Code string      // 授权码
type UIDRP string     // RP-specific pseudonym uid_rp
type Acid []byte      // 匿名 RP 标识 acid
type AUid []byte      // OPRF 中的 a_uid

type DHKeyPair struct {
	Priv *lib.DHKey
	Pub  *lib.DHKey
}

type ServerCredKey struct {
	PSKey1 *lib.PSKey
	PSKey2 *lib.PSKey
}
type ServerCredPk struct {
	Vk1 *lib.PSPublicKey // Verification key for Sign1.
	Vk2 *lib.PSPublicKey // Verification key for Sign2.
}

// 域名凭证：DC = (D, σ)
type DomainCredential struct {
	Domain []byte         // D
	Sigma  *lib.PSSignMsg // PS 签名等
}

// 秘密凭证：SC = (D, rpkIK, σ̄)
type SecretCredential struct {
	Domain     []byte           // D
	IdentitySk *bls12381.Scalar // RP 身份私钥 rpkIK
	SigmaBar   *lib.PSSignMsg   // 对 (D, rpkIK) 的 PS 签名
}

type AAKEEphemeralKey struct {
	ID string
	SK *bls12381.Scalar
	PK *bls12381.G1
}
