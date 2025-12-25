package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"

	"crypto/rand"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/iden3/go-iden3-crypto/poseidon"
)

var (
	// SNARK_FIELD_SIZE is the size of the BN254 scalar field
	SNARK_FIELD_SIZE, _ = new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)
)

// GenerateSecureRandomBigInt generates a cryptographically secure random BigInt
func GenerateSecureRandomBigInt() (*big.Int, error) {
	// 31 bytes to stay within field size
	b := make([]byte, 31)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}

// Sha256 returns the byte slice of the SHA256 hash of the input
func Sha256(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

// Sha256Hex returns the hex string of the SHA256 hash of the input
func Sha256Hex(data []byte) string {
	return hex.EncodeToString(Sha256(data))
}

// SplitHashToFieldElements splits a 256-bit hash (hex string) into two 128-bit chunks
func SplitHashToFieldElements(hexString string) (*fr.Element, *fr.Element) {
	fullValue := new(big.Int)
	fullValue.SetString(hexString, 16)

	mask128 := new(big.Int).Lsh(big.NewInt(1), 128)
	mask128.Sub(mask128, big.NewInt(1))

	p1Int := new(big.Int).And(fullValue, mask128)
	p2Int := new(big.Int).Rsh(fullValue, 128)
	p2Int.And(p2Int, mask128)

	var p1, p2 fr.Element
	p1.SetBigInt(p1Int)
	p2.SetBigInt(p2Int)

	return &p1, &p2
}

// PoseidonHash computes the Poseidon hash of the given field elements
func PoseidonHash(inputs []*fr.Element) (*fr.Element, error) {
	in := make([]*big.Int, len(inputs))
	for i, v := range inputs {
		in[i] = new(big.Int)
		v.BigInt(in[i])
	}

	res, err := poseidon.Hash(in)
	if err != nil {
		return nil, err
	}

	var hash fr.Element
	hash.SetBigInt(res)
	return &hash, nil
}

// Base27 encodes a big integer into a base27 string using the alphabet "abcdefghijklmnopqrstuvwxyz-"
func Base27(n *big.Int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz-"

	if n.Sign() == 0 {
		return string(alphabet[0])
	}

	base := big.NewInt(27)
	zero := big.NewInt(0)
	var result []byte

	mod := new(big.Int)
	nCopy := new(big.Int).Set(n)

	for nCopy.Cmp(zero) > 0 {
		nCopy.DivMod(nCopy, base, mod)
		result = append(result, alphabet[mod.Int64()])
	}

	// Reverse result
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	return string(result)
}

// DeriveHostnameFromCommitment derives the hostname from the commitment (fr.Element)
func DeriveHostnameFromCommitment(commitment *fr.Element, domain string) (string, error) {
	// To 32-bytes Little Endian Buffer
	// Reference: commitmentBuff = leInt2Buff(commitment, 32)
	bytes := commitment.Bytes() // This is usually Big Endian in gnark-crypto

	// Convert to Little Endian
	leBytes := make([]byte, 32)
	for i := 0; i < 32; i++ {
		leBytes[i] = bytes[31-i]
	}

	// SHA256
	hashBytes := sha256.Sum256(leBytes)

	// Base27 of hash
	n := new(big.Int).SetBytes(hashBytes[:]) // reference uses LargeInteger = BigInt('0x' + hexString)
	// Base27 function takes big.Int
	encoded := Base27(n)

	return fmt.Sprintf("x%sx", encoded), nil
}
