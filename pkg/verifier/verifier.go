package verifier

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Stygian-Inc/ptx-jesuit-go/pkg/dns"
	"github.com/Stygian-Inc/ptx-jesuit-go/pkg/nonce"
	"github.com/Stygian-Inc/ptx-jesuit-go/pkg/ptxloader"
	"github.com/Stygian-Inc/ptx-jesuit-go/pkg/signals"
	"github.com/Stygian-Inc/ptx-jesuit-go/pkg/utils"
	"github.com/Stygian-Inc/ptx-jesuit-go/pkg/vk"
	"github.com/Stygian-Inc/ptx-jesuit-go/ptx"
	"github.com/vocdoni/circom2gnark/parser"
)

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

	// Parse Proof Data
	// Extract public signals and inner proof
	var wrapper struct {
		PublicSignals []string        `json:"publicSignals"`
		Proof         json.RawMessage `json:"proof"`
	}
	if err := json.Unmarshal(proof.ProofData, &wrapper); err != nil {
		return ZkResult{Valid: false, Error: "Invalid proof wrapper JSON"}
	}

	// Parse Proof using circom2gnark
	circomProof, err := parser.UnmarshalCircomProofJSON(wrapper.Proof)
	if err != nil {
		return ZkResult{Valid: false, Error: "Invalid inner proof JSON: " + err.Error()}
	}

	domain := ""
	if ptxFile.GetDohDetails() != nil {
		domain = ptxFile.GetDohDetails().GetDomainName()
	}

	// Semantic Verification
	sig := signals.NewPTXSignals(domain, metaRaw, ptxFile.GetTrustMethod())
	semVerify := sig.VerifyAgainstProof(wrapper.PublicSignals)

	if !semVerify.AllValid {
		return ZkResult{Valid: false, Semantic: false, Error: "Semantic verification failed"}
	}

	// Cryptographic Verification
	// startTime := time.Now()

	// Load VK (Circom format)
	// We use verification_key.json as it contains necessary schema info for circom2gnark
	circomVk, err := vk.LoadCircomKey("verification_key.json")
	if err != nil {
		return ZkResult{Valid: false, Error: "Failed to load VK: " + err.Error()}
	}

	// Convert everything to GnarkProof
	// This helper handles witness construction from public signals using the VK schema
	gnarkProof, err := parser.ConvertCircomToGnark(circomProof, circomVk, wrapper.PublicSignals)
	if err != nil {
		return ZkResult{Valid: false, Error: "Circom to Gnark conversion failed: " + err.Error()}
	}
	startTime := time.Now()
	// Verify using parser's helper
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
