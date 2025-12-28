package poseidon

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
)

// Parameters for Poseidon hash
type Parameters struct {
	T        int        // State width (nInputs + 1)
	NRoundsF int        // Full rounds
	NRoundsP int        // Partial rounds
	C        []string   // Round constants
	M        [][]string // MDS matrix
	P        [][]string // Pre-sparse matrix
	S        []string   // Sparse matrix elements
}

// GetParams returns parameters for given t value
func GetParams(t int) (*Parameters, error) {
	nRoundsP := []int{56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68}

	var c []string
	var m, p [][]string
	var s []string

	switch t {
	case 2:
		c = C_T2
		m = M_T2
		p = P_T2
		s = S_T2
	case 4:
		c = C_T4
		m = M_T4
		p = P_T4
		s = S_T4
	case 5:
		c = C_T5
		m = M_T5
		p = P_T5
		s = S_T5
	default:
		return nil, fmt.Errorf("unsupported t value: %d", t)
	}

	return &Parameters{
		T:        t,
		NRoundsF: 8,
		NRoundsP: nRoundsP[t-2],
		C:        c,
		M:        m,
		P:        p,
		S:        s,
	}, nil
}

// Hasher implements Poseidon hash for gnark circuits
type Hasher struct {
	api    frontend.API
	params *Parameters
}

// NewHasher creates a new Poseidon hasher for given number of inputs
func NewHasher(api frontend.API, nInputs int) (*Hasher, error) {
	t := nInputs + 1
	params, err := GetParams(t)
	if err != nil {
		return nil, err
	}
	return &Hasher{api: api, params: params}, nil
}

// sBox applies x^5 S-box
func (h *Hasher) sBox(x frontend.Variable) frontend.Variable {
	x2 := h.api.Mul(x, x)
	x4 := h.api.Mul(x2, x2)
	return h.api.Mul(x4, x)
}

// arkAtOffset adds round constants starting at given offset in C array
func (h *Hasher) arkAtOffset(state []frontend.Variable, offset int) {
	t := h.params.T
	for i := 0; i < t; i++ {
		c := new(big.Int)
		c.SetString(h.params.C[offset+i][2:], 16) // Strip 0x prefix
		state[i] = h.api.Add(state[i], c)
	}
}

// mix applies MDS matrix multiplication
func (h *Hasher) mix(state []frontend.Variable, matrix [][]string) []frontend.Variable {
	t := h.params.T
	result := make([]frontend.Variable, t)

	for i := 0; i < t; i++ {
		acc := frontend.Variable(0)
		for j := 0; j < t; j++ {
			m := new(big.Int)
			m.SetString(matrix[j][i][2:], 16)
			term := h.api.Mul(state[j], m)
			acc = h.api.Add(acc, term)
		}
		result[i] = acc
	}
	return result
}

// mixS applies sparse matrix multiplication for partial rounds
func (h *Hasher) mixS(state []frontend.Variable, round int) []frontend.Variable {
	t := h.params.T
	result := make([]frontend.Variable, t)
	sOffset := (t*2 - 1) * round

	// First element is a dot product
	acc := frontend.Variable(0)
	for i := 0; i < t; i++ {
		s := new(big.Int)
		s.SetString(h.params.S[sOffset+i][2:], 16)
		term := h.api.Mul(state[i], s)
		acc = h.api.Add(acc, term)
	}
	result[0] = acc

	// Remaining elements
	for i := 1; i < t; i++ {
		s := new(big.Int)
		s.SetString(h.params.S[sOffset+t+i-1][2:], 16)
		term := h.api.Mul(state[0], s)
		result[i] = h.api.Add(state[i], term)
	}

	return result
}

// Hash computes Poseidon hash of inputs following the exact Circom PoseidonEx algorithm
func (h *Hasher) Hash(inputs ...frontend.Variable) (frontend.Variable, error) {
	if len(inputs) != h.params.T-1 {
		return nil, fmt.Errorf("expected %d inputs, got %d", h.params.T-1, len(inputs))
	}

	t := h.params.T
	rf := h.params.NRoundsF
	rp := h.params.NRoundsP

	// Initialize state: [0, input[0], input[1], ...]
	state := make([]frontend.Variable, t)
	state[0] = frontend.Variable(0)
	for i, inp := range inputs {
		state[i+1] = inp
	}

	// Initial ark at offset 0
	h.arkAtOffset(state, 0)

	// First half of full rounds (nRoundsF/2 - 1 rounds)
	for r := 0; r < rf/2-1; r++ {
		for i := 0; i < t; i++ {
			state[i] = h.sBox(state[i])
		}
		h.arkAtOffset(state, (r+1)*t)
		state = h.mix(state, h.params.M)
	}

	// Middle full round with S-box, ark, and P-matrix mix
	for i := 0; i < t; i++ {
		state[i] = h.sBox(state[i])
	}
	h.arkAtOffset(state, (rf/2)*t)
	state = h.mix(state, h.params.P)

	// Partial rounds
	for r := 0; r < rp; r++ {
		state[0] = h.sBox(state[0])
		// Add round constant to first element only
		cIdx := (rf/2+1)*t + r
		c := new(big.Int)
		c.SetString(h.params.C[cIdx][2:], 16)
		state[0] = h.api.Add(state[0], c)
		state = h.mixS(state, r)
	}

	// Second half of full rounds (nRoundsF/2 - 1 rounds)
	for r := 0; r < rf/2-1; r++ {
		for i := 0; i < t; i++ {
			state[i] = h.sBox(state[i])
		}
		h.arkAtOffset(state, (rf/2+1)*t+rp+r*t)
		state = h.mix(state, h.params.M)
	}

	// Final full round: S-box only, then final mix with M
	for i := 0; i < t; i++ {
		state[i] = h.sBox(state[i])
	}
	state = h.mix(state, h.params.M)

	return state[0], nil
}

// Hash1 is a convenience function for hashing 1 input
func Hash1(api frontend.API, a frontend.Variable) (frontend.Variable, error) {
	h, err := NewHasher(api, 1)
	if err != nil {
		return nil, err
	}
	return h.Hash(a)
}

// Hash3 is a convenience function for hashing 3 inputs
func Hash3(api frontend.API, a, b, c frontend.Variable) (frontend.Variable, error) {
	h, err := NewHasher(api, 3)
	if err != nil {
		return nil, err
	}
	return h.Hash(a, b, c)
}

// Hash4 is a convenience function for hashing 4 inputs
func Hash4(api frontend.API, a, b, c, d frontend.Variable) (frontend.Variable, error) {
	h, err := NewHasher(api, 4)
	if err != nil {
		return nil, err
	}
	return h.Hash(a, b, c, d)
}
