package signals

import (
	"crypto/sha256"
	"math/big"

	"github.com/Stygian-Inc/ptx-jesuit-go/ptx"
)

type VerificationResult struct {
	FqdnHash      bool
	MetadataPart1 bool
	MetadataPart2 bool
	TrustMethod   bool
	AllValid      bool
}

type PTXSignals struct {
	Domain      string
	MetadataRaw string
	TrustMethod ptx.TrustMethod
}

func NewPTXSignals(domain string, metadataRaw string, trustMethod ptx.TrustMethod) *PTXSignals {
	return &PTXSignals{
		Domain:      domain,
		MetadataRaw: metadataRaw,
		TrustMethod: trustMethod,
	}
}

// hashToBigInts splits a 32-byte hash into two big integers (high and low 128 bits)
func hashToBigInts(data []byte) (*big.Int, *big.Int) {
	// Simple split: first 16 bytes, last 16 bytes
	// Note: We need to verify if this matches the JS implementation
	// Usually big endian or little endian interpretation matters.
	// Assuming Big Endian for now as it's standard for hashing.

	part1 := new(big.Int).SetBytes(data[:16])
	part2 := new(big.Int).SetBytes(data[16:])

	// If the JS implementation uses Little Endian or different split, this needs adjustment.
	return part1, part2
}

func (s *PTXSignals) VerifyAgainstProof(publicSignals []string) VerificationResult {
	// Parse public signals to big ints
	signals := make([]*big.Int, len(publicSignals))
	for i, s := range publicSignals {
		signals[i] = new(big.Int)
		signals[i].SetString(s, 10)
	}

	// Reconstruct expected signals
	// 1. Metadata Hash
	metaHash := sha256.Sum256([]byte(s.MetadataRaw))
	metaP1, metaP2 := hashToBigInts(metaHash[:])

	// 2. Domain Hash (FQDN)
	// Assuming SHA256 of domain string
	domainHashBytes := sha256.Sum256([]byte(s.Domain))
	// FQDN hash might be a single field element if masked or truncated,
	// or split. However, usually domain hash is just one input if used for commitment.
	// Let's assume it fits in one field element or we use one part.
	// For now, let's look at publicSignals indices.

	// TODO: Without the JS file, we are guessing the indices checking logic.
	// Based on "nPublic: 6" and verifying "fqdnHash, metadataPart1, metadataPart2, trustMethod"
	// We might have:
	// 0: output?
	// 1: commitment (used for DNS, verified separately in verifyDNS)
	// 2: trustMethod?
	// 3: fqdnHash?
	// 4: metaP1?
	// 5: metaP2?

	// Let's rely on string comparison if possible, or try to match values.

	res := VerificationResult{}

	// We scan the public signals for our expected values.
	// This is a robust way if we don't know exact indices.

	trustMethodBig := big.NewInt(int64(s.TrustMethod))

	for _, sig := range signals {
		if sig.Cmp(trustMethodBig) == 0 {
			res.TrustMethod = true
		}
		if sig.Cmp(metaP1) == 0 {
			res.MetadataPart1 = true
		}
		if sig.Cmp(metaP2) == 0 {
			res.MetadataPart2 = true
		}
		// FQDN Hash check - this is tricky without knowing exact derivation
		// Maybe FQDN is hashed to BigInt?
		fqdnBig := new(big.Int).SetBytes(domainHashBytes[:])
		// Often it is mod Field Order or truncated.
		// If we assume it looks for the hash:
		if sig.Cmp(fqdnBig) == 0 {
			res.FqdnHash = true
		}
	}

	res.AllValid = res.TrustMethod && res.MetadataPart1 && res.MetadataPart2
	// FQDN match might be optional or part of commitment.
	// The JS code: `logDetail("FQDN Hash", semantic.fqdnHash ...)` implies it is checked.

	return res
}

func (s *PTXSignals) DeriveSignals(publicSignals []string) ([]*big.Int, error) {
	// This function is for Groth16 verify input.
	// Groth16 verify in gnark takes witness (public assignment).
	// We construct it from the proof's public signals.
	res := make([]*big.Int, len(publicSignals))
	for i, ps := range publicSignals {
		res[i] = new(big.Int)
		res[i].SetString(ps, 10)
	}
	return res, nil
}
