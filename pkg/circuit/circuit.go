package circuit

import (
	"github.com/Stygian-Inc/ptx-jesuit-go/pkg/circuit/poseidon"
	"github.com/consensys/gnark/frontend"
)

// DoHCircuit defines the constraints for the Signed Data Verification (SDV) circuit.
type DoHCircuit struct {
	// Public inputs
	NullifierHash  frontend.Variable `gnark:",public"`
	Commitment     frontend.Variable `gnark:",public"`
	Fqdn           frontend.Variable `gnark:",public"`
	MetadataHashP1 frontend.Variable `gnark:",public"`
	MetadataHashP2 frontend.Variable `gnark:",public"`
	TrustMethod    frontend.Variable `gnark:",public"`

	// Private inputs
	Nullifier frontend.Variable
	Secret    frontend.Variable
}

// Define declares the circuit constraints
func (c *DoHCircuit) Define(api frontend.API) error {
	// 1. Context Hash = Poseidon(fqdn, metadataHash_p1, metadataHash_p2, trustMethod)
	contextHash, err := poseidon.Hash4(api, c.Fqdn, c.MetadataHashP1, c.MetadataHashP2, c.TrustMethod)
	if err != nil {
		return err
	}

	// 2. Nullifier Hash = Poseidon(nullifier)
	calcNullifierHash, err := poseidon.Hash1(api, c.Nullifier)
	if err != nil {
		return err
	}

	// 3. Commitment = Poseidon(nullifier, secret, contextHash)
	calcCommitment, err := poseidon.Hash3(api, c.Nullifier, c.Secret, contextHash)
	if err != nil {
		return err
	}

	// 4. Constraints
	api.AssertIsEqual(c.NullifierHash, calcNullifierHash)
	api.AssertIsEqual(c.Commitment, calcCommitment)

	return nil
}
