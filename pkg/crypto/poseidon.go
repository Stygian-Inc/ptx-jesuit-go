package crypto

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// Poseidon parameters - matches Circom implementation
var nRoundsP = []int{56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68}

// getFr converts hex string to fr.Element
func getFr(hexStr string) *fr.Element {
	bi := new(big.Int)
	bi.SetString(hexStr[2:], 16) // Skip 0x prefix
	var f fr.Element
	f.SetBigInt(bi)
	return &f
}

// PoseidonHash computes Poseidon hash of field elements using Circom-compatible parameters
// This implementation follows the exact algorithm in poseidon.circom
func PoseidonHash(inputs []*fr.Element) (*fr.Element, error) {
	nInputs := len(inputs)
	t := nInputs + 1

	var c, s []string
	var m, p [][]string

	switch t {
	case 2:
		c = poseidonC2
		m = poseidonM2
		p = poseidonP2
		s = poseidonS2
	case 4:
		c = poseidonC4
		m = poseidonM4
		p = poseidonP4
		s = poseidonS4
	case 5:
		c = poseidonC5
		m = poseidonM5
		p = poseidonP5
		s = poseidonS5
	default:
		return nil, fmt.Errorf("unsupported number of inputs: %d (t=%d)", nInputs, t)
	}

	nRoundsF := 8
	nRoundsP := nRoundsP[t-2]

	// Helper: S-box (x^5)
	sBox := func(x *fr.Element) *fr.Element {
		x2 := new(fr.Element).Mul(x, x)
		x4 := new(fr.Element).Mul(x2, x2)
		return new(fr.Element).Mul(x4, x)
	}

	// Helper: Add round constants
	ark := func(state []*fr.Element, r int) {
		for i := 0; i < t; i++ {
			state[i].Add(state[i], getFr(c[i+r]))
		}
	}

	// Helper: MDS mix
	mix := func(state []*fr.Element, matrix [][]string) []*fr.Element {
		result := make([]*fr.Element, t)
		for i := 0; i < t; i++ {
			result[i] = new(fr.Element).SetZero()
			for j := 0; j < t; j++ {
				term := new(fr.Element).Mul(state[j], getFr(matrix[j][i]))
				result[i].Add(result[i], term)
			}
		}
		return result
	}

	// Helper: Sparse mix for partial rounds
	mixS := func(state []*fr.Element, r int) []*fr.Element {
		result := make([]*fr.Element, t)
		sOffset := (t*2 - 1) * r

		// First element is a dot product
		result[0] = new(fr.Element).SetZero()
		for i := 0; i < t; i++ {
			term := new(fr.Element).Mul(state[i], getFr(s[sOffset+i]))
			result[0].Add(result[0], term)
		}

		// Remaining elements
		for i := 1; i < t; i++ {
			result[i] = new(fr.Element).Add(state[i], new(fr.Element).Mul(state[0], getFr(s[sOffset+t+i-1])))
		}

		return result
	}

	// Initialize state: [initialState=0, inputs[0], inputs[1], ...]
	state := make([]*fr.Element, t)
	state[0] = new(fr.Element).SetZero()
	for i := 0; i < nInputs; i++ {
		state[i+1] = new(fr.Element).Set(inputs[i])
	}

	// === Following the exact poseidon.circom PoseidonEx algorithm ===

	// Initial ark at round 0
	ark(state, 0)

	// First half of full rounds (nRoundsF/2 - 1 rounds)
	for r := 0; r < nRoundsF/2-1; r++ {
		for i := 0; i < t; i++ {
			state[i] = sBox(state[i])
		}
		ark(state, (r+1)*t)
		state = mix(state, m)
	}

	// Middle full round with S-box, ark, and P-matrix mix
	for i := 0; i < t; i++ {
		state[i] = sBox(state[i])
	}
	ark(state, (nRoundsF/2)*t)
	state = mix(state, p)

	// Partial rounds
	for r := 0; r < nRoundsP; r++ {
		state[0] = sBox(state[0])
		// Add round constant to first element only
		state[0].Add(state[0], getFr(c[(nRoundsF/2+1)*t+r]))
		state = mixS(state, r)
	}

	// Second half of full rounds (nRoundsF/2 - 1 rounds)
	for r := 0; r < nRoundsF/2-1; r++ {
		for i := 0; i < t; i++ {
			state[i] = sBox(state[i])
		}
		ark(state, (nRoundsF/2+1)*t+nRoundsP+r*t)
		state = mix(state, m)
	}

	// Final full round: S-box only, then final mix with M
	for i := 0; i < t; i++ {
		state[i] = sBox(state[i])
	}
	state = mix(state, m)

	// Return first element of the state (equivalent to mixLast in Circom)
	return state[0], nil
}

// CircuitHash is an alias for PoseidonHash for compatibility
func CircuitHash(inputs []*fr.Element) (*fr.Element, error) {
	return PoseidonHash(inputs)
}
