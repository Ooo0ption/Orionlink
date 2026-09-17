package common

import (
	"encoding/base64"

	"github.com/cloudflare/circl/ecc/bls12381"
)

/************************     Basic Struct Serialization       ************************/
func ScalarToBytes(scalar *bls12381.Scalar) []byte {
	if scalar == nil {
		return nil
	}
	// Use MarshalBinary provided by the circl implementation which returns
	// a fixed-length big-endian representation suitable for storage.
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

func BytesToString(b []byte) string {
	if b == nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(b)
}

func StringToBytes(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(s)
}

func ScalarToString(scalar *bls12381.Scalar) string {
	if scalar == nil {
		return ""
	}
	return BytesToString(ScalarToBytes(scalar))
}

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

func G1ToBytes(point *bls12381.G1) []byte {
	if point == nil {
		return nil
	}
	return point.BytesCompressed()
}

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
func G2ToBytes(point *bls12381.G2) []byte {
	if point == nil {
		return nil
	}
	return point.BytesCompressed()
}

func G1ToString(point *bls12381.G1) string {
	if point == nil {
		return ""
	}
	return BytesToString(point.BytesCompressed())
}

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

func G2ToString(point *bls12381.G2) string {
	if point == nil {
		return ""
	}
	return BytesToString(point.BytesCompressed())
}

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
