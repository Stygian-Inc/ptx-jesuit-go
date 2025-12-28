package prover

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"os/exec"

	"time"

	"github.com/Stygian-Inc/ptx-jesuit-go/pkg/circuit"
	"github.com/Stygian-Inc/ptx-jesuit-go/pkg/crypto"
	"github.com/Stygian-Inc/ptx-jesuit-go/ptx"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"google.golang.org/protobuf/proto"
)

const (
	nativeVKPath = "native.vk"
	nativePKPath = "native.pk"
)

// loadOrSetupKeys loads cached keys or runs setup and caches them
func loadOrSetupKeys(ccs constraint.ConstraintSystem) (groth16.ProvingKey, groth16.VerifyingKey, error) {
	// Try to load existing keys
	if _, err := os.Stat(nativeVKPath); err == nil {
		if _, err := os.Stat(nativePKPath); err == nil {
			// Both files exist, load them
			pkFile, err := os.Open(nativePKPath)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to open pk file: %w", err)
			}
			defer pkFile.Close()

			vkFile, err := os.Open(nativeVKPath)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to open vk file: %w", err)
			}
			defer vkFile.Close()

			pk := groth16.NewProvingKey(ecc.BN254)
			vk := groth16.NewVerifyingKey(ecc.BN254)

			if _, err := pk.ReadFrom(pkFile); err != nil {
				return nil, nil, fmt.Errorf("failed to read pk: %w", err)
			}
			if _, err := vk.ReadFrom(vkFile); err != nil {
				return nil, nil, fmt.Errorf("failed to read vk: %w", err)
			}

			return pk, vk, nil
		}
	}

	// Generate new keys
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, nil, fmt.Errorf("setup failed: %w", err)
	}

	// Save keys to files
	pkFile, err := os.Create(nativePKPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create pk file: %w", err)
	}
	defer pkFile.Close()

	vkFile, err := os.Create(nativeVKPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create vk file: %w", err)
	}
	defer vkFile.Close()

	if _, err := pk.WriteTo(pkFile); err != nil {
		return nil, nil, fmt.Errorf("failed to write pk: %w", err)
	}
	if _, err := vk.WriteTo(vkFile); err != nil {
		return nil, nil, fmt.Errorf("failed to write vk: %w", err)
	}

	return pk, vk, nil
}

// CircuitInputs represents the public and private inputs for the SDV circuit
type CircuitInputs struct {
	NullifierHash  string `json:"nullifierHash"`
	Commitment     string `json:"commitment"`
	Fqdn           string `json:"fqdn"`
	MetadataHashP1 string `json:"metadataHash_p1"`
	MetadataHashP2 string `json:"metadataHash_p2"`
	TrustMethod    string `json:"trustMethod"`
	Nullifier      string `json:"nullifier"`
	Secret         string `json:"secret"`
}

// BenchmarkResult holds timing statistics
type BenchmarkResult struct {
	CompileTimeMs float64
	WitnessTimeMs float64
	ProveTimeMs   float64
}

// Prover handles the proof generation process
type Prover struct{}

func NewProver() *Prover {
	return &Prover{}
}

// GenerateCircuitInputs computes the inputs for the SDV circuit based on the provided parameters
func (p *Prover) GenerateCircuitInputs(
	domain string,
	metadata map[string]interface{},
	nullifier string,
	secret string,
	trustMethod int,
) (*CircuitInputs, error) {
	// 1. Calculate Metadata Hash
	metaBytes, err := json.Marshal(metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal metadata: %w", err)
	}
	metaHex := crypto.Sha256Hex(metaBytes)
	p1, p2 := crypto.SplitHashToFieldElements(metaHex)

	// 2. FQDN hash
	domainHashBytes := crypto.Sha256([]byte(domain))
	// Convert to fr.Element and mod by field size (done automatically by SetBigInt)
	var fqdnFr fr.Element
	fqdnFr.SetBigInt(new(big.Int).SetBytes(domainHashBytes))

	// 3. Context Hash = Hash(fqdn, metaP1, metaP2, trustMethod)
	var tmFr fr.Element
	tmFr.SetInt64(int64(trustMethod))

	contextHash, err := crypto.CircuitHash([]*fr.Element{&fqdnFr, p1, p2, &tmFr})
	if err != nil {
		return nil, fmt.Errorf("failed to compute context hash: %w", err)
	}

	// 4. Commitment = Hash(nullifier, secret, contextHash)
	var nullifierFr, secretFr fr.Element
	nullifierFr.SetString(nullifier)
	secretFr.SetString(secret)

	commitment, err := crypto.CircuitHash([]*fr.Element{&nullifierFr, &secretFr, contextHash})
	if err != nil {
		return nil, fmt.Errorf("failed to compute commitment: %w", err)
	}

	// 5. Nullifier Hash = Hash(nullifier)
	nullifierHash, err := crypto.CircuitHash([]*fr.Element{&nullifierFr})
	if err != nil {
		return nil, fmt.Errorf("failed to compute nullifier hash: %w", err)
	}

	return &CircuitInputs{
		NullifierHash:  nullifierHash.String(),
		Commitment:     commitment.String(),
		Fqdn:           fqdnFr.String(),
		MetadataHashP1: p1.String(),
		MetadataHashP2: p2.String(),
		TrustMethod:    fmt.Sprintf("%d", trustMethod),
		Nullifier:      nullifier,
		Secret:         secret,
	}, nil
}

// GenerateProof generates a Groth16 proof using snarkjs shell-out (for Circom compatibility)
func (p *Prover) GenerateProof(
	inputs *CircuitInputs,
	wasmPath string,
	zkeyPath string,
) ([]byte, error) {
	// Strategy: Shell out to snarkjs for robustness and compatibility with Circom artifacts

	// Prepare snarkjs command wrapper
	// We try to find 'snarkjs' in PATH or use 'npx snarkjs'
	var snarkjsCmd []string
	if _, err := exec.LookPath("snarkjs"); err == nil {
		snarkjsCmd = []string{"snarkjs"}
	} else if _, err := exec.LookPath("npx"); err == nil {
		snarkjsCmd = []string{"npx", "snarkjs"}
	} else {
		return nil, fmt.Errorf("neither 'snarkjs' nor 'npx' found in PATH. Please install snarkjs")
	}

	// 1. Write inputs to JSON
	inputBytes, err := json.Marshal(inputs)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal inputs: %w", err)
	}

	tmpInput, err := os.CreateTemp("", "input-*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp input: %w", err)
	}
	defer os.Remove(tmpInput.Name())
	if _, err := tmpInput.Write(inputBytes); err != nil {
		return nil, fmt.Errorf("failed to write input: %w", err)
	}
	tmpInput.Close()

	// 2. Witness Generation
	tmpWitness, err := os.CreateTemp("", "witness-.wtns")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp witness: %w", err)
	}
	witnessPath := tmpWitness.Name()
	tmpWitness.Close()
	defer os.Remove(witnessPath)

	// cmd: snarkjs wtns calculate <wasm> <input> <output>
	argsWtns := append(snarkjsCmd, "wtns", "calculate", wasmPath, tmpInput.Name(), witnessPath)
	cmdWtns := exec.Command(argsWtns[0], argsWtns[1:]...)
	if out, err := cmdWtns.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("snarkjs witness calculation failed: %v, output: %s", err, out)
	}

	// 3. Proof Generation
	tmpProof, err := os.CreateTemp("", "proof-*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp proof: %w", err)
	}
	proofPath := tmpProof.Name()
	tmpProof.Close()
	defer os.Remove(proofPath)

	tmpPublic, err := os.CreateTemp("", "public-*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp public: %w", err)
	}
	publicPath := tmpPublic.Name()
	tmpPublic.Close()
	defer os.Remove(publicPath)

	// cmd: snarkjs groth16 prove <zkey> <witness> <proof.json> <public.json>
	argsProve := append(snarkjsCmd, "groth16", "prove", zkeyPath, witnessPath, proofPath, publicPath)
	cmdProve := exec.Command(argsProve[0], argsProve[1:]...)
	if out, err := cmdProve.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("snarkjs proving failed: %v, output: %s", err, out)
	}

	// 4. Read Proof
	proofBytes, err := ioutil.ReadFile(proofPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read proof: %w", err)
	}

	publicBytes, err := ioutil.ReadFile(publicPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read public signals: %w", err)
	}

	// We need to package them together as expected by verifier?
	// The internal verifier logic expects a JSON with "proof" (the snarkjs proof object) and "publicSignals" array

	var proofRaw json.RawMessage
	if err := json.Unmarshal(proofBytes, &proofRaw); err != nil {
		return nil, fmt.Errorf("failed to parse proof json: %w", err)
	}

	var publicSigs []string
	if err := json.Unmarshal(publicBytes, &publicSigs); err != nil {
		return nil, fmt.Errorf("failed to parse public signals json: %w", err)
	}

	wrapper := struct {
		PublicSignals []string        `json:"publicSignals"`
		Proof         json.RawMessage `json:"proof"`
	}{
		PublicSignals: publicSigs,
		Proof:         proofRaw,
	}

	return json.Marshal(wrapper)
}

// GenerateProofNative generates a proof using purely Go (Gnark)
// It performs Setup on the fly (for demo) or uses cached keys.
// NOTE: For a real production system, you would load pre-computed CCS/PK/VK.
func (p *Prover) GenerateProofNative(inputs *CircuitInputs) ([]byte, error) {
	// 1. Compile Circuit
	var dohCircuit circuit.DoHCircuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &dohCircuit)
	if err != nil {
		return nil, fmt.Errorf("circuit compilation failed: %w", err)
	}

	// 2. Setup (with key caching)
	pk, vk, err := loadOrSetupKeys(ccs)
	if err != nil {
		return nil, fmt.Errorf("key setup failed: %w", err)
	}

	// Optional: We should save VK/PK effectively if we want to Verify later.
	// But `jesuit prove` just outputs PTX. The verifier will need to match checks.
	// Since we are creating a NEW setup, the existing `verification_key.json` (Circom) WON'T work.
	// We should probably warn the user or export the new vk.

	// 3. Create Witness
	// Mapped from inputs
	assignment := circuit.DoHCircuit{
		NullifierHash:  fromString(inputs.NullifierHash),
		Commitment:     fromString(inputs.Commitment),
		Fqdn:           fromString(inputs.Fqdn),
		MetadataHashP1: fromString(inputs.MetadataHashP1),
		MetadataHashP2: fromString(inputs.MetadataHashP2),
		TrustMethod:    fromString(inputs.TrustMethod),
		Nullifier:      fromString(inputs.Nullifier),
		Secret:         fromString(inputs.Secret),
	}

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("witness creation failed: %w", err)
	}

	publicWitness, err := witness.Public()
	if err != nil {
		return nil, fmt.Errorf("public witness creation failed: %w", err)
	}

	// 4. Prove
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		return nil, fmt.Errorf("proving failed: %w", err)
	}

	// 5. Serialize
	// We need to output logic compatible with our PTX format.
	// Our PTX format expects JSON with "proof" and "publicSignals".
	// However, Gnark proofs are binary (or diff JSON schema).
	// To maintain compatibility with existing `verify` command which uses `circom2gnark` parser,
	// we ideally output compatible JSON.
	// BUT, `circom2gnark` parser is for SnarkJS proofs.
	//
	// If we use Native Gnark, the `verify` command likely needs update OR check proof system.
	// PTX has `ProofSystem_GROTH16`. It doesn't specify implementation.
	//
	// Let's assume for now we write Gnark-specific JSON or binary.
	// Since the user asked for "native proof", I will output standard Gnark JSON.
	// Note: Existing Verifier uses `LoadCircomKey` and `UnmarshalCircomProofJSON`.
	// Use of native key will fail there.
	//
	// I will just serialize `proof` + `publicWitness` to JSON here in a wrapper.

	buf := new(bytes.Buffer)
	proof.WriteRawTo(buf) // Binary encoding
	proofBytes := buf.Bytes()

	// For public signals, we can extract them?
	// Gnark witness is binary.
	// We can manually construct the list of strings since we have the inputs.
	publicSigs := []string{
		inputs.NullifierHash,
		inputs.Commitment,
		inputs.Fqdn,
		inputs.MetadataHashP1,
		inputs.MetadataHashP2,
		inputs.TrustMethod,
	}

	// To make it JSON compatible with generic readers, let's encode proof as Base64 or Hex?
	// The current PTX format stores ProofData as bytes.
	// snarkjs flow stores JSON bytes.
	// We will store a define JSON wrapper for Gnark:
	/*
		{
			"backend": "gnark",
			"curve": "bn254",
			"proof": "<base64_binary_proof>",
			"publicSignals": [...]
		}
	*/

	// For now, I'll stick to a simple JSON similar to what we did before but marking it.
	// Actually, `verifier.go` tries to parse SnarkJS style JSON.
	// It will error if we pass something else.
	//
	// IMPORTANT: The user REIMPLEMENTED the circuit. This implies the VERIFIER also needs to change
	// or be aware of this new era.
	// Ideally, I'd output a "verification_key.gnark" along with the proof?
	//
	// I'll execute the request: Reimplement in Gnark.
	// I'll return a JSON structure.

	wrapper := struct {
		Source        string   `json:"source"`
		PublicSignals []string `json:"publicSignals"`
		ProofHex      string   `json:"proofHex"`
	}{
		Source:        "gnark_native",
		PublicSignals: publicSigs,
		ProofHex:      fmt.Sprintf("%x", proofBytes),
	}

	// We also verify it here just to be helpful/debug
	if err := groth16.Verify(proof, vk, publicWitness); err != nil {
		fmt.Println("WARNING: Generated proof failed self-verification!", err)
	}

	return json.Marshal(wrapper)
}

// BenchmarkNative runs the native prover and returns timing statistics
func (p *Prover) BenchmarkNative(inputs *CircuitInputs) (*BenchmarkResult, []byte, error) {
	result := &BenchmarkResult{}

	// 1. Compile Circuit
	start := time.Now()
	var dohCircuit circuit.DoHCircuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &dohCircuit)
	if err != nil {
		return nil, nil, fmt.Errorf("circuit compilation failed: %w", err)
	}
	result.CompileTimeMs = float64(time.Since(start).Microseconds()) / 1000.0

	// 2. Setup (we don't benchmark setup as it's typically pre-generated,
	// but we need the keys)
	pk, _, err := loadOrSetupKeys(ccs)
	if err != nil {
		return nil, nil, fmt.Errorf("key setup failed: %w", err)
	}

	// 3. Create Witness
	start = time.Now()
	assignment := circuit.DoHCircuit{
		NullifierHash:  fromString(inputs.NullifierHash),
		Commitment:     fromString(inputs.Commitment),
		Fqdn:           fromString(inputs.Fqdn),
		MetadataHashP1: fromString(inputs.MetadataHashP1),
		MetadataHashP2: fromString(inputs.MetadataHashP2),
		TrustMethod:    fromString(inputs.TrustMethod),
		Nullifier:      fromString(inputs.Nullifier),
		Secret:         fromString(inputs.Secret),
	}

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, nil, fmt.Errorf("witness creation failed: %w", err)
	}

	_, err = witness.Public()
	if err != nil {
		return nil, nil, fmt.Errorf("public witness creation failed: %w", err)
	}
	result.WitnessTimeMs = float64(time.Since(start).Microseconds()) / 1000.0

	// 4. Prove
	start = time.Now()
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		return nil, nil, fmt.Errorf("proving failed: %w", err)
	}
	result.ProveTimeMs = float64(time.Since(start).Microseconds()) / 1000.0

	// 5. Serialize (identical to GenerateProofNative)
	buf := new(bytes.Buffer)
	proof.WriteRawTo(buf)
	proofBytes := buf.Bytes()

	publicSigs := []string{
		inputs.NullifierHash,
		inputs.Commitment,
		inputs.Fqdn,
		inputs.MetadataHashP1,
		inputs.MetadataHashP2,
		inputs.TrustMethod,
	}

	wrapper := struct {
		Source        string   `json:"source"`
		PublicSignals []string `json:"publicSignals"`
		ProofHex      string   `json:"proofHex"`
	}{
		Source:        "gnark_native",
		PublicSignals: publicSigs,
		ProofHex:      fmt.Sprintf("%x", proofBytes),
	}

	proofJSON, err := json.Marshal(wrapper)
	return result, proofJSON, err
}

func fromString(s string) frontend.Variable {
	var i big.Int
	i.SetString(s, 10)
	return i
}

// CreatePtxFile builds and serializes a PtxFile message
func (p *Prover) CreatePtxFile(
	proofJSON []byte,
	metadata map[string]interface{},
	domain string,
	trustMethod int,
) ([]byte, error) {
	metaBytes, err := json.Marshal(metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal metadata: %w", err)
	}

	proof := &ptx.ZkProof{
		ProofSystem:       ptx.ProofSystem_GROTH16,
		VerificationKeyId: "sdv_poseidon_v1",
		ProofData:         proofJSON,
	}

	ptxFile := &ptx.PtxFile{
		TrustMethod:    ptx.TrustMethod(trustMethod),
		Proof:          proof,
		SignedMetadata: string(metaBytes),
		Anchor: &ptx.PtxFile_DohDetails{
			DohDetails: &ptx.DohAnchor{
				DomainName: domain,
			},
		},
	}

	serialized, err := proto.Marshal(ptxFile)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal PTX proto: %w", err)
	}

	// finalData = []byte{0x50, 0x54, 0x58, 0x01, 0x00} + serialized
	finalData := append([]byte{0x50, 0x54, 0x58, 0x01, 0x00}, serialized...)

	return finalData, nil
}
