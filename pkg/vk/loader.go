package vk

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/vocdoni/circom2gnark/parser"
)

// LoadCircomKey loads a SnarkJS JSON verification key
func LoadCircomKey(path string) (*parser.CircomVerificationKey, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read VK file: %w", err)
	}

	circomVk, err := parser.UnmarshalCircomVerificationKeyJSON(data)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal circom VK: %w", err)
	}

	return circomVk, nil
}

// LoadBinaryKey loads a Gnark native binary verification key
func LoadBinaryKey(path string) (groth16.VerifyingKey, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open VK file: %w", err)
	}
	defer f.Close()

	vk := groth16.NewVerifyingKey(ecc.BN254)
	if _, err := vk.ReadFrom(f); err != nil {
		return nil, fmt.Errorf("failed to parse binary VK: %w", err)
	}

	return vk, nil
}
