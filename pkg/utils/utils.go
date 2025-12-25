package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
)

// Sha256 returns the hex string of the SHA256 hash of the input string
func Sha256(str string) string {
	hash := sha256.Sum256([]byte(str))
	return hex.EncodeToString(hash[:])
}

// Base27 encodes a hex string into a base27 string using the alphabet "abcdefghijklmnopqrstuvwxyz-"
func Base27(hexStr string) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz-"

	n := new(big.Int)
	n.SetString(hexStr, 16)

	if n.Sign() == 0 {
		return string(alphabet[0])
	}

	base := big.NewInt(27)
	zero := big.NewInt(0)
	var result []byte

	mod := new(big.Int)

	for n.Cmp(zero) > 0 {
		n.DivMod(n, base, mod)
		result = append(result, alphabet[mod.Int64()])
	}

	// Reverse result
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	return string(result)
}

// DeriveHostnameFromCommitment derives the hostname from the commitment
func DeriveHostnameFromCommitment(commitmentStr string, domain string) (string, error) {
	// 1. Parse Decimal String to BigInt
	n := new(big.Int)
	n.SetString(commitmentStr, 10)
	if n.Sign() == 0 && commitmentStr != "0" {
		return "", fmt.Errorf("failed to parse commitment: %s", commitmentStr)
	}

	// 2. To 32-bytes Little Endian Buffer
	bytes := make([]byte, 32)
	// Write bytes in Little Endian
	beBytes := n.Bytes()

	// Copy to LE buffer
	for i := 0; i < len(beBytes); i++ {
		if i < 32 {
			bytes[i] = beBytes[len(beBytes)-1-i]
		}
	}

	// 3. SHA256
	hashBytes := sha256.Sum256(bytes)
	hashHex := hex.EncodeToString(hashBytes[:])

	// 4. Base27 of hash
	encoded := Base27(hashHex)

	return fmt.Sprintf("x%sx.%s", encoded, domain), nil
}
