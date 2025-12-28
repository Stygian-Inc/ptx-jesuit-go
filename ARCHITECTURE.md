# Jesuit Architecture

This document describes the internal structure and design of the Jesuit PTX tool.

## Project Structure

```text
jesuit/
├── cmd/
│   └── jesuit/             # CLI entrypoints (cobra commands)
├── pkg/
│   ├── circuit/            # Gnark ZK-SNARK circuit definitions
│   │   └── poseidon/       # Circom-compatible Poseidon implementation
│   ├── crypto/             # Off-circuit crypto (Poseidon, SHA256, formatting)
│   ├── dns/                # DNS TXT record lookup utilities
│   ├── nonce/              # Redis-backed nonce management
│   ├── prover/             # Native Go proof generation logic
│   ├── ptxloader/          # PTX file deserialization and validation
│   ├── signals/            # Semantic verification of public signals
│   ├── utils/              # General helper functions
│   └── verifier/           # Unified verification engine
└── ptx/                    # Protocol Buffer definitions (PTX format)
```

## Core Components

### 1. The Circuit (`pkg/circuit`)
The `DoHCircuit` is implemented using the `gnark` frontend. It ensures that:
- The `NullifierHash` is the Poseidon hash of the `Nullifier`.
- The `Commitment` is the Poseidon hash of `(Nullifier, Secret, ContextHash)`.
- The `ContextHash` combines the `FQDN`, `Metadata`, and `TrustMethod`.

### 2. Poseidon Implementation (`pkg/circuit/poseidon`)
A critical requirement for cross-compatibility was matching the `poseidon.circom` logic. This included:
- Extracted round constants and MDS matrices from Circom sources.
- Custom `ark`, `sbox`, and `mix` functions using the `gnark` frontend API.
- Implementation of `PoseidonEx` logic for handling inputs of varying lengths.

### 3. Unified Verifier (`pkg/verifier`)
The verifier is designed to be extensible. When checking a proof, it:
1. Unmarshals a JSON wrapper to determine the `source` (`gnark_native` or legacy).
2. Performs **Semantic Verification**: it re-calculates what the public signals *should* be based on the metadata and domain specified in the PTX file.
3. Performs **Cryptographic Verification**:
   - For `gnark_native`, it compiles the circuit on-the-fly (or loads cached R1CS) and verifies using Groth16.
   - For legacy proofs, it uses `circom2gnark` translation to verify Circom proofs within the Go environment.

### 4. Benchmarking Engine
The benchmarking system is integrated directly into the `Prover` and `Verifier` structs. It captures:
- **Off-circuit time**: Input parsing, SHA256 hashing.
- **Circuit time**: Compilation, Witness generation, and Proving.
- **Network time**: DNS lookup latency.

## Key Management
Native proving/verification relies on deterministic keys. If `native.pk` or `native.vk` are missing, they are generated using `groth16.Setup`. For multi-party environments, the same `native.vk` must be distributed to all verifiers.
