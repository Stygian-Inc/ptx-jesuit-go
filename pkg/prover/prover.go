package prover

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"os/exec"

	"github.com/Stygian-Inc/ptx-jesuit-go/pkg/crypto"
	"github.com/Stygian-Inc/ptx-jesuit-go/ptx"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"google.golang.org/protobuf/proto"
)

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

	// 3. Context Hash = Poseidon(fqdn, metaP1, metaP2, trustMethod)
	var tmFr fr.Element
	tmFr.SetInt64(int64(trustMethod))

	contextHash, err := crypto.PoseidonHash([]*fr.Element{&fqdnFr, p1, p2, &tmFr})
	if err != nil {
		return nil, fmt.Errorf("failed to compute context hash: %w", err)
	}

	// 4. Commitment = Poseidon(nullifier, secret, contextHash)
	var nullifierFr, secretFr fr.Element
	nullifierFr.SetString(nullifier)
	secretFr.SetString(secret)

	commitment, err := crypto.PoseidonHash([]*fr.Element{&nullifierFr, &secretFr, contextHash})
	if err != nil {
		return nil, fmt.Errorf("failed to compute commitment: %w", err)
	}

	// 5. Nullifier Hash = Poseidon(nullifier)
	nullifierHash, err := crypto.PoseidonHash([]*fr.Element{&nullifierFr})
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

// GenerateProof generates a Groth16 proof using snarkjs shell-out
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
