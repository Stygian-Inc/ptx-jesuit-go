package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/Stygian-Inc/ptx-jesuit-go/pkg/crypto"
	"github.com/Stygian-Inc/ptx-jesuit-go/pkg/prover"
	"github.com/spf13/cobra"
)

var (
	domain      string
	fqdn        string
	metadataStr string
	metaHex     string
	nullifier   string
	secret      string
	proofFile   string
	outFile     string
	trustMethod int
	zkeyPath    string
	wasmPath    string
	r1csPath    string
)

var proveCmd = &cobra.Command{
	Use:   "prove",
	Short: "Generate proof inputs or a PTX file",
	Long:  `Generate the necessary inputs for ZK-SNARK proof generation, or create a final .ptx file if a proof is provided.`,
	Run: func(cmd *cobra.Command, args []string) {
		if domain == "" && fqdn == "" {
			fmt.Println("Error: --domain or --fqdn is required")
			os.Exit(1)
		}

		if fqdn != "" {
			domain = fqdn
		}

		// 1. Parse Metadata
		var metadata map[string]interface{}
		if metaHex != "" {
			decoded, err := hex.DecodeString(metaHex)
			if err != nil {
				fmt.Printf("Error: Invalid hex-encoded metadata: %v\n", err)
				os.Exit(1)
			}
			metadataStr = string(decoded)
		}
		if metadataStr != "" {
			if err := json.Unmarshal([]byte(metadataStr), &metadata); err != nil {
				fmt.Printf("Error: Invalid metadata JSON: %v\n", err)
				os.Exit(1)
			}
		} else {
			metadata = make(map[string]interface{})
		}

		// 2. Handle Secrets
		if nullifier == "" || secret == "" {
			fmt.Println("No nullifier or secret provided. Generating secure random values...")
			n, _ := crypto.GenerateSecureRandomBigInt()
			s, _ := crypto.GenerateSecureRandomBigInt()
			nullifier = n.String()
			secret = s.String()
			fmt.Printf("Nullifier: %s\n", nullifier)
			fmt.Printf("Secret:    %s\n", secret)
		}

		p := prover.NewProver()

		// 3. Generate Inputs
		inputs, err := p.GenerateCircuitInputs(domain, metadata, nullifier, secret, trustMethod)
		if err != nil {
			fmt.Printf("Error generating circuit inputs: %v\n", err)
			os.Exit(1)
		}

		// Use crypto package for hostname derivation to show it
		// commitment, _ := new(fr.Element).SetString(inputs.Commitment)
		// Wait, I'll just print the inputs JSON
		inputsJSON, _ := json.MarshalIndent(inputs, "", "  ")
		fmt.Println("\n--- Circuit Inputs (for snarkjs) ---")
		fmt.Println(string(inputsJSON))

		// 4. Handle Proof and PTX creation
		var proofData []byte

		if zkeyPath != "" && wasmPath != "" {
			fmt.Println("Generating ZK Proof using gnark...")
			proofData, err = p.GenerateProof(inputs, wasmPath, zkeyPath)
			if err != nil {
				fmt.Printf("Error generating proof: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("Proof generated successfully!")
			// If we generated proof internally, we populate proofData
		} else if proofFile != "" {
			proofData, err = ioutil.ReadFile(proofFile)
			if err != nil {
				fmt.Printf("Error reading proof file: %v\n", err)
				os.Exit(1)
			}
		}

		if len(proofData) > 0 {
			ptxData, err := p.CreatePtxFile(proofData, metadata, domain, trustMethod)
			if err != nil {
				fmt.Printf("Error creating PTX file: %v\n", err)
				os.Exit(1)
			}
			// ... (rest of writing file)
			if outFile == "" {
				outFile = "output.ptx"
			}

			if err := ioutil.WriteFile(outFile, ptxData, 0644); err != nil {
				fmt.Printf("Error writing PTX file: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("\nSuccessfully generated PTX file: %s\n", outFile)
		} else {
			fmt.Println("\nTip: To generate a full PTX file, provide:")
			fmt.Println("     1. A proof file via --proof <proof.json>")
			fmt.Println("     OR")
			fmt.Println("     2. Circuit artifacts via --zkey <file.zkey> AND --wasm <file.wasm>")
		}
	},
}

func init() {
	rootCmd.AddCommand(proveCmd)

	proveCmd.Flags().StringVar(&domain, "domain", "", "Domain name for DoH anchor")
	proveCmd.Flags().StringVar(&fqdn, "fqdn", "", "Fully Qualified Domain Name (alias for --domain)")
	proveCmd.Flags().StringVar(&metadataStr, "metadata", "", "Metadata JSON string")
	proveCmd.Flags().StringVar(&metaHex, "metadataString", "", "Hex-encoded metadata JSON string")
	proveCmd.Flags().StringVar(&nullifier, "nullifier", "", "Nullifier (decimal string)")
	proveCmd.Flags().StringVar(&secret, "secret", "", "Secret (decimal string)")
	proveCmd.Flags().StringVar(&proofFile, "proof", "", "Path to snarkjs proof JSON file")
	proveCmd.Flags().StringVar(&outFile, "out", "output.ptx", "Output path for the generated .ptx file")
	proveCmd.Flags().IntVar(&trustMethod, "trustMethod", 1, "Trust method (1=DOH, 2=GIST)")
	proveCmd.Flags().StringVar(&zkeyPath, "zkey", "", "Path to .zkey file for proof generation")
	proveCmd.Flags().StringVar(&wasmPath, "wasm", "", "Path to .wasm file for witness generation")
	proveCmd.Flags().StringVar(&r1csPath, "r1cs", "", "Path to .r1cs file (optional for some provers)")
}
