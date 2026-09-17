// Shared types of the OrionLink protocol: identifiers, credentials and key material.
package common

import (
	"secure-sso/lib"

	"github.com/cloudflare/circl/ecc/bls12381"
)

// Logical identifiers used across the three roles.
type RPID string
type BrokerID string
type UserID string
type SessionID string
type Code string
type UIDRP string
type Acid []byte
type AUid []byte

// DHKeyPair pairs a private and a public Diffie-Hellman key.
type DHKeyPair struct {
	Priv *lib.DHKey
	Pub  *lib.DHKey
}

// ServerCredKey is the IdP's credential signing material: PSKey1 signs the
// DomainCred, PSKey2 blind-signs the SecretCred.
type ServerCredKey struct {
	PSKey1 *lib.PSKey
	PSKey2 *lib.PSKey
}

// ServerCredPk is the public half of ServerCredKey, as published to RPs.
type ServerCredPk struct {
	Vk1 *lib.PSPublicKey
	Vk2 *lib.PSPublicKey
}

// DomainCredential is the RP's DomainCred DC = (D, sigma).
type DomainCredential struct {
	Domain []byte
	Sigma  *lib.PSSignMsg
}

// SecretCredential is the RP's SecretCred SC = (D, rpk_IK, sigma_bar).
type SecretCredential struct {
	Domain     []byte
	IdentitySk *bls12381.Scalar
	SigmaBar   *lib.PSSignMsg
}

// AAKEEphemeralKey is one ephemeral X3DH key pair, addressed by its ID.
type AAKEEphemeralKey struct {
	ID string
	SK *bls12381.Scalar
	PK *bls12381.G1
}
