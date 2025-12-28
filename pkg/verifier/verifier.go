package verifier

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/Stygian-Inc/ptx-jesuit-go/pkg/circuit"
	"github.com/Stygian-Inc/ptx-jesuit-go/pkg/crypto"
	"github.com/Stygian-Inc/ptx-jesuit-go/pkg/dns"
	"github.com/Stygian-Inc/ptx-jesuit-go/pkg/nonce"
	"github.com/Stygian-Inc/ptx-jesuit-go/pkg/ptxloader"
	"github.com/Stygian-Inc/ptx-jesuit-go/pkg/signals"
	"github.com/Stygian-Inc/ptx-jesuit-go/pkg/utils"
	"github.com/Stygian-Inc/ptx-jesuit-go/pkg/vk"
	"github.com/Stygian-Inc/ptx-jesuit-go/ptx"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/vocdoni/circom2gnark/parser"
)

const nativeVKPath = "native.vk"

// loadCachedVK loads the verification key from cache or runs setup if not found
func loadCachedVK(ccs constraint.ConstraintSystem) (groth16.VerifyingKey, error) {
	// Try to load existing VK
	if _, err := os.Stat(nativeVKPath); err == nil {
		vkFile, err := os.Open(nativeVKPath)
		if err != nil {
			return nil, fmt.Errorf("failed to open vk file: %w", err)
		}
		defer vkFile.Close()

		vk := groth16.NewVerifyingKey(ecc.BN254)
		if _, err := vk.ReadFrom(vkFile); err != nil {
			return nil, fmt.Errorf("failed to read vk: %w", err)
		}
		return vk, nil
	}

	// VK doesn't exist, must generate (first run or keys missing)
	// Note: This will create different keys than the prover if called first!
	_, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, fmt.Errorf("setup failed: %w", err)
	}

	// Save VK for future use
	vkFile, err := os.Create(nativeVKPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create vk file: %w", err)
	}
	defer vkFile.Close()

	if _, err := vk.WriteTo(vkFile); err != nil {
		return nil, fmt.Errorf("failed to write vk: %w", err)
	}

	return vk, nil
}

type VerificationOptions struct {
	FilePath         string
	IntendedScope    []string
	IntendedAudience []string
	StrictMode       bool
	RedisURL         string
	Verbose          bool
}

type VerificationResult struct {
	Success bool
	Errors  []string
	Dns     DnsResult
	Zk      ZkResult
	Details VerificationDetails
}

type VerificationDetails struct {
	Fqdn           string
	FqdnHash       string
	MetadataJSON   string
	MetadataHashP1 string
	MetadataHashP2 string
	TrustMethod    string
	NullifierHash  string
	Commitment     string
}

type DnsResult struct {
	Valid           bool
	Error           string
	DerivedHostname string
	FetchTimeMs     float64
}

type ZkResult struct {
	Valid       bool
	Skipped     bool
	Semantic    bool
	Error       string
	ProofTimeMs float64
}

type PTXVerifier struct {
	Options VerificationOptions
}

func NewPTXVerifier(opts VerificationOptions) *PTXVerifier {
	return &PTXVerifier{Options: opts}
}

func (v *PTXVerifier) Verify() (*VerificationResult, error) {
	res := &VerificationResult{
		Success: true,
		Errors:  []string{},
	}

	// 1. Load PTX
	ptxFile, err := ptxloader.LoadPTX(v.Options.FilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load PTX file: %w", err)
	}

	// 2. Metadata & Semantic Checks
	metaRaw := ptxFile.GetSignedMetadata()
	var meta map[string]interface{}
	if err := json.Unmarshal([]byte(metaRaw), &meta); err != nil {
		res.Success = false
		res.Errors = append(res.Errors, "Invalid metadata JSON")
		return res, nil
	}

	// Check Expiration
	if exp, ok := meta["expiration_timestamp"].(float64); ok {
		if time.Now().Unix() > int64(exp) {
			res.Success = false
			res.Errors = append(res.Errors, "PTX token expired")
		}
	}

	// Check Scope
	if len(v.Options.IntendedScope) > 0 {
		if scopes, ok := meta["scopes"].([]interface{}); ok {
			found := false
			for _, s := range scopes {
				for _, req := range v.Options.IntendedScope {
					if s.(string) == req {
						found = true
						break
					}
				}
			}
			if !found {
				res.Success = false
				res.Errors = append(res.Errors, "Scope mismatch")
			}
		}
	}

	// Check Audience
	if len(v.Options.IntendedAudience) > 0 {
		if aud, ok := meta["audience"].(string); ok {
			found := false
			for _, req := range v.Options.IntendedAudience {
				if aud == req {
					found = true
					break
				}
			}
			if !found {
				res.Success = false
				res.Errors = append(res.Errors, "Audience mismatch")
			}
		}
	}

	// Nonce Check
	if v.Options.RedisURL != "" {
		if nonceVal, ok := meta["nonce"].(string); ok {
			st, err := nonce.NewNonceStore(v.Options.RedisURL)
			if err != nil {
				res.Success = false
				res.Errors = append(res.Errors, "Failed to connect to nonce store: "+err.Error())
				return res, nil
			}
			defer st.Close()

			// Use expiration from metadata or default to 5 min TTL
			var exp int64 = 300
			if e, ok := meta["expiration_timestamp"].(float64); ok {
				exp = int64(e)
			}

			valid, err := st.CheckAndSetNonce(nonceVal, exp)
			if err != nil || !valid {
				res.Success = false
				res.Errors = append(res.Errors, "Nonce invalid or replayed")
			}
		}
	}

	// 3. DNS Verification
	res.Dns = v.verifyDNS(ptxFile)
	if !res.Dns.Valid {
		res.Success = false
	}

	// 4. ZK Verification
	res.Zk = v.verifyProof(ptxFile, metaRaw)
	if !res.Zk.Valid && !res.Zk.Skipped {
		res.Success = false
		res.Errors = append(res.Errors, "ZK proof invalid: "+res.Zk.Error)
	}

	// 5. Populate Details for verbose output
	// Try to get nullifierHash and commitment from proof if possible
	nullifierHash := ""
	commitment := ""
	proof := ptxFile.GetProof()
	if proof != nil {
		var pd struct {
			PublicSignals []string `json:"publicSignals"`
		}
		if err := json.Unmarshal(proof.ProofData, &pd); err == nil && len(pd.PublicSignals) >= 2 {
			nullifierHash = pd.PublicSignals[0]
			commitment = pd.PublicSignals[1]
		}
	}

	domain := ""
	if ptxFile.GetDohDetails() != nil {
		domain = ptxFile.GetDohDetails().GetDomainName()
	}
	fqdnHash, _ := crypto.PoseidonHashString(domain)
	metaP1, metaP2 := crypto.SplitMetadataHash(metaRaw)

	res.Details = VerificationDetails{
		Fqdn:           domain,
		FqdnHash:       fqdnHash.String(),
		MetadataJSON:   metaRaw,
		MetadataHashP1: metaP1.String(),
		MetadataHashP2: metaP2.String(),
		TrustMethod:    fmt.Sprintf("%d", ptxFile.GetTrustMethod()),
		NullifierHash:  nullifierHash,
		Commitment:     commitment,
	}

	return res, nil
}

func (v *PTXVerifier) verifyDNS(ptxFile *ptx.PtxFile) DnsResult {
	doh := ptxFile.GetDohDetails()
	if doh == nil {
		return DnsResult{Error: "No DoH details found"}
	}

	com := ptxFile.GetProof()
	if com == nil {
		return DnsResult{Error: "No proof found for commitment extraction"}
	}

	var pd struct {
		PublicSignals []string `json:"publicSignals"`
	}
	if err := json.Unmarshal(com.ProofData, &pd); err != nil {
		return DnsResult{Error: "Failed to parse proof public signals"}
	}

	if len(pd.PublicSignals) < 2 {
		return DnsResult{Error: "Insufficient public signals for commitment extraction"}
	}
	commitment := pd.PublicSignals[1]

	hostname, err := utils.DeriveHostnameFromCommitment(commitment, doh.GetDomainName())
	if err != nil {
		return DnsResult{Error: "Hostname derivation failed: " + err.Error()}
	}

	// Expected content in TXT record is SHA256 of metadata
	expected := utils.Sha256(ptxFile.GetSignedMetadata())

	// Check DNS
	startTime := time.Now()
	txt, err := dns.GetTXT(hostname)
	elapsed := time.Since(startTime).Seconds() * 1000

	if err != nil {
		return DnsResult{Valid: false, Error: "DNS Lookup failed: " + err.Error(), DerivedHostname: hostname, FetchTimeMs: elapsed}
	}

	found := false
	for _, record := range txt {
		if strings.Contains(record, expected) {
			found = true
			break
		}
	}

	if found {
		return DnsResult{Valid: true, DerivedHostname: hostname, FetchTimeMs: elapsed}
	}

	return DnsResult{Valid: false, Error: "No matching TXT record found (Expected: " + expected + ")", DerivedHostname: hostname, FetchTimeMs: elapsed}
}

func (v *PTXVerifier) verifyProof(ptxFile *ptx.PtxFile, metaRaw string) ZkResult {
	proof := ptxFile.GetProof()
	if proof == nil {
		return ZkResult{Valid: false, Error: "No proof present"}
	}

	// Logic check for Groth16 if we only support that for now
	if proof.GetProofSystem() != ptx.ProofSystem_GROTH16 {
		return ZkResult{Skipped: true, Valid: false, Error: "Unsupported Proof System (only Groth16 supported)"}
	}

	// Parse Proof Data to detect source
	var wrapper struct {
		Source        string          `json:"source"`
		PublicSignals []string        `json:"publicSignals"`
		Proof         json.RawMessage `json:"proof"`
		ProofHex      string          `json:"proofHex"`
	}
	if err := json.Unmarshal(proof.ProofData, &wrapper); err != nil {
		return ZkResult{Valid: false, Error: "Invalid proof wrapper JSON"}
	}

	domain := ""
	if ptxFile.GetDohDetails() != nil {
		domain = ptxFile.GetDohDetails().GetDomainName()
	}

	// Semantic Verification (same for both proof types)
	sig := signals.NewPTXSignals(domain, metaRaw, ptxFile.GetTrustMethod())
	semVerify := sig.VerifyAgainstProof(wrapper.PublicSignals)

	if !semVerify.AllValid {
		return ZkResult{Valid: false, Semantic: false, Error: "Semantic verification failed"}
	}

	// Branch based on proof source
	if wrapper.Source == "gnark_native" {
		// For native Gnark proofs, re-derive public signals from PTX data
		// Only nullifierHash and commitment come from the proof
		return v.verifyNativeGnarkProof(wrapper.ProofHex, wrapper.PublicSignals, domain, metaRaw, ptxFile.GetTrustMethod())
	}

	// Fallback: Circom/snarkjs proof verification
	return v.verifyCircomProof(wrapper.Proof, wrapper.PublicSignals)
}

func (v *PTXVerifier) verifyCircomProof(proofJSON json.RawMessage, publicSignals []string) ZkResult {
	// Parse Proof using circom2gnark
	circomProof, err := parser.UnmarshalCircomProofJSON(proofJSON)
	if err != nil {
		return ZkResult{Valid: false, Error: "Invalid inner proof JSON: " + err.Error()}
	}

	// Load VK (Circom format)
	circomVk, err := vk.LoadCircomKey("verification_key.json")
	if err != nil {
		return ZkResult{Valid: false, Error: "Failed to load VK: " + err.Error()}
	}

	// Convert everything to GnarkProof
	gnarkProof, err := parser.ConvertCircomToGnark(circomProof, circomVk, publicSignals)
	if err != nil {
		return ZkResult{Valid: false, Error: "Circom to Gnark conversion failed: " + err.Error()}
	}

	startTime := time.Now()
	valid, err := parser.VerifyProof(gnarkProof)
	elapsed := time.Since(startTime).Seconds() * 1000

	if err != nil {
		return ZkResult{Valid: false, Error: "Verification failed: " + err.Error()}
	}
	if !valid {
		return ZkResult{Valid: false, Error: "Verification returned false"}
	}

	return ZkResult{Valid: true, Semantic: true, ProofTimeMs: elapsed}
}

func (v *PTXVerifier) verifyNativeGnarkProof(proofHex string, proofSignals []string, domain string, metaRaw string, trustMethod ptx.TrustMethod) ZkResult {
	startTime := time.Now()

	// Decode proof bytes from hex
	proofBytes, err := hex.DecodeString(proofHex)
	if err != nil {
		return ZkResult{Valid: false, Error: "Failed to decode proof hex: " + err.Error()}
	}

	// Compile the same circuit to get the constraint system
	var dohCircuit circuit.DoHCircuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &dohCircuit)
	if err != nil {
		return ZkResult{Valid: false, Error: "Circuit compilation failed: " + err.Error()}
	}

	// Load cached VK (must match the prover's VK)
	gnarkVK, err := loadCachedVK(ccs)
	if err != nil {
		return ZkResult{Valid: false, Error: "Failed to load VK: " + err.Error()}
	}

	// Reconstruct the proof from bytes
	proof := groth16.NewProof(ecc.BN254)
	_, err = proof.ReadFrom(bytes.NewReader(proofBytes))
	if err != nil {
		return ZkResult{Valid: false, Error: "Failed to deserialize proof: " + err.Error()}
	}

	// RE-DERIVE public signals from PTX data (SECURITY CRITICAL)
	// Only nullifierHash and commitment come from the proof
	// fqdn, metadataHashP1, metadataHashP2, trustMethod are derived from PTX file

	if len(proofSignals) < 2 {
		return ZkResult{Valid: false, Error: "Insufficient public signals in proof (need nullifierHash and commitment)"}
	}

	// Get nullifierHash and commitment from proof (these are the actual proof outputs)
	nullifierHash := proofSignals[0]
	commitment := proofSignals[1]

	// Re-derive fqdn hash using Poseidon (same as prover)
	fqdnHash, err := crypto.PoseidonHashString(domain)
	if err != nil {
		return ZkResult{Valid: false, Error: "Failed to compute fqdn hash: " + err.Error()}
	}

	// Re-derive metadata hash parts
	metaP1, metaP2 := crypto.SplitMetadataHash(metaRaw)

	// Build public witness with re-derived signals
	assignment := circuit.DoHCircuit{
		NullifierHash:  fromStringV(nullifierHash),
		Commitment:     fromStringV(commitment),
		Fqdn:           fqdnHash,
		MetadataHashP1: metaP1,
		MetadataHashP2: metaP2,
		TrustMethod:    int(trustMethod),
		// Private inputs not needed for public witness
		Nullifier: 0,
		Secret:    0,
	}

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		return ZkResult{Valid: false, Error: "Witness creation failed: " + err.Error()}
	}

	publicWitness, err := witness.Public()
	if err != nil {
		return ZkResult{Valid: false, Error: "Public witness extraction failed: " + err.Error()}
	}

	// Verify the proof
	err = groth16.Verify(proof, gnarkVK, publicWitness)
	elapsed := time.Since(startTime).Seconds() * 1000

	if err != nil {
		return ZkResult{Valid: false, Error: "Native Gnark verification failed: " + err.Error()}
	}

	return ZkResult{Valid: true, Semantic: true, ProofTimeMs: elapsed}
}

func fromStringV(s string) frontend.Variable {
	var i big.Int
	i.SetString(s, 10)
	return i
}
