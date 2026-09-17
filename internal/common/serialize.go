// Serialization between BLS12-381 values and their byte / base64 wire encodings.
package common

import (
	"encoding/base64"

	"github.com/cloudflare/circl/ecc/bls12381"
)

// ScalarToBytes encodes a scalar with MarshalBinary.
func ScalarToBytes(scalar *bls12381.Scalar) []byte {
	if scalar == nil {
		return nil
	}
	b, err := scalar.MarshalBinary()
	if err != nil {
		return nil
	}
	return b
}

// BytesToScalar reconstructs a Scalar from bytes produced by MarshalBinary.
func BytesToScalar(b []byte) (*bls12381.Scalar, error) {
	var s bls12381.Scalar
	if err := s.UnmarshalBinary(b); err != nil {
		return nil, err
	}
	return &s, nil
}

// BytesToString base64-encodes a byte slice for transport.
func BytesToString(b []byte) string {
	if b == nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(b)
}

// StringToBytes decodes a base64 string back into bytes.
func StringToBytes(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(s)
}

// ScalarToString encodes a scalar as base64.
func ScalarToString(scalar *bls12381.Scalar) string {
	if scalar == nil {
		return ""
	}
	return BytesToString(ScalarToBytes(scalar))
}

// StringToScalar decodes a base64 scalar.
func StringToScalar(s string) (*bls12381.Scalar, error) {
	if s == "" {
		return nil, nil
	}
	b, err := StringToBytes(s)
	if err != nil {
		return nil, err
	}
	return BytesToScalar(b)
}

// G1ToBytes encodes a G1 point in compressed form.
func G1ToBytes(point *bls12381.G1) []byte {
	if point == nil {
		return nil
	}
	return point.BytesCompressed()
}

// BytesToG1 decodes a compressed G1 point.
func BytesToG1(b []byte) (*bls12381.G1, error) {
	if b == nil {
		return nil, nil
	}
	var point bls12381.G1
	if err := point.SetBytes(b); err != nil {
		return nil, err
	}
	return &point, nil
}

// BytesToG2 decodes a compressed G2 point.
func BytesToG2(b []byte) (*bls12381.G2, error) {
	if b == nil {
		return nil, nil
	}
	var point bls12381.G2
	if err := point.SetBytes(b); err != nil {
		return nil, err
	}
	return &point, nil
}

// G2ToBytes encodes a G2 point in compressed form.
func G2ToBytes(point *bls12381.G2) []byte {
	if point == nil {
		return nil
	}
	return point.BytesCompressed()
}

// G1ToString encodes a G1 point as compressed base64.
func G1ToString(point *bls12381.G1) string {
	if point == nil {
		return ""
	}
	return BytesToString(point.BytesCompressed())
}

// StringToG1 decodes a base64 compressed G1 point.
func StringToG1(data string) (*bls12381.G1, error) {
	if data == "" {
		return nil, nil
	}
	bytes, err := StringToBytes(data)
	if err != nil {
		return nil, err
	}
	var point bls12381.G1
	point.SetBytes(bytes)
	return &point, nil
}

// G2ToString encodes a G2 point as compressed base64.
func G2ToString(point *bls12381.G2) string {
	if point == nil {
		return ""
	}
	return BytesToString(point.BytesCompressed())
}

// StringToG2 decodes a base64 compressed G2 point.
func StringToG2(data string) (*bls12381.G2, error) {
	if data == "" {
		return nil, nil
	}
	bytes, err := StringToBytes(data)
	if err != nil {
		return nil, err
	}
	var point bls12381.G2
	point.SetBytes(bytes)
	return &point, nil
}
