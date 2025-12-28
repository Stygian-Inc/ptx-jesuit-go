# Jesuit: Portable Trust eXtensible (PTX)

Jesuit is a high-performance, security-focused system for generating and verifying **Portable Trust eXtensible (PTX)** records. Built in Go, it leverages `gnark` for zero-knowledge proofs (zk-SNARKs) to provide decentralised, verifiable trust anchored in DNS (via DoH).

---

## Overview

Jesuit enables entities to prove possession of metadata associated with a domain without revealing sensitive secrets, ensuring that trust is portable, extensible, and mathematically verifiable.

### Key Features
- **Native Go zk-SNARK Prover**: High-performance proof generation using the `gnark` framework.
- **Cross-Compatible Poseidon**: Bit-for-bit compatible with `poseidon.circom` for interoperability with Circom-based systems.
- **Hybrid Verification**: Support for both native Go proofs and legacy Circom/snarkjs proofs.
- **DNS-Anchored Integrity**: Verification is anchored to DNS TXT records, preventing spoofing via semantic checks.
- **Deep Benchmarking**: Real-time analysis of witness generation, circuit compilation, and network latency.

---

## Prerequisites

Before building Jesuit, ensure your environment meets the following requirements:

- **Go**: `v1.25.3` or higher
- **Redis**: `v8.4.0` or higher (Required for nonce management and state tracking)
- **Protobuf**: `libprotoc 33.2` or higher (For compiling `.proto` definitions)
- **macOS**: Optimized for Darwin/ARM64 and Darwin/AMD64.

---

## Installation

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd Jesuit
   ```

2. **Install dependencies**:
   ```bash
   go mod tidy
   ```

3. **Build the CLI**:
   ```bash
   go build -o jesuit ./cmd/jesuit
   ```

---

## Usage

### 1. Generating a Proof (`prove`)
Generate a PTX proof for a specific domain and metadata payload.

```bash
./jesuit prove --domain stygian.io --metadata '{"role":"validator"}'
```

**Benchmarking Mode**:
Run iterative benchmarks to analyze proving performance.
```bash
./jesuit prove --domain example.com --benchmark --benchmark-runs 10
```

### 2. Verifying a Proof (`verify`)
Verify the cryptographic and semantic validity of a `.ptx` file.

```bash
./jesuit verify output.ptx
```

**Verbose Diagnostics**:
Show re-derived hostnames and internal signal calculations.
```bash
./jesuit verify -v output.ptx
```

### 3. Variated Benchmarking
Stress-test the system by varying input parameters like FQDN length or metadata size.

```bash
# Vary FQDN length from 5 to 255
./jesuit variated-benchmark --target fqdn --range 5,255,10 --runs 5 --stats
```

---

## 🏗 Architecture

Jesuit is organized into modular packages for clarity and extensibility:

- `cmd/jesuit`: CLI entrypoints and command logic.
- `pkg/circuit`: `gnark` circuit definitions and Poseidon implementations.
- `pkg/crypto`: Off-circuit cryptographic primitives and hashing.
- `pkg/prover`: Proof generation orchestration.
- `pkg/verifier`: Logical and cryptographic verification engine.
- `ptx/`: Protobuf definitions for the PTX format.

For a deep dive into the system design, see [ARCHITECTURE.md](file:///Users/leviackerman/Projects/Turin/Jesuit/ARCHITECTURE.md).

---

## Key Management

Upon first execution, Jesuit will perform a one-time Groth16 setup. The resulting parameters are cached locally:

- `native.pk`: Proving Key (Keep private if used in production)
- `native.vk`: Verification Key (Distribute to verifiers)

Sharing the `native.vk` ensures that all verifiers are checking against the same circuit parameters.

---

## License

Copyright 2025 Abhinav Vishnu

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.