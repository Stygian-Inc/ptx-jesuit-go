package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/vocdoni/circom2gnark/parser"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: convert-keys <verification_key.bin> [output.bin]")
		os.Exit(1)
	}

	inputFile := os.Args[1]
	outputFile := "verification_key.bin"
	if len(os.Args) > 2 {
		outputFile = os.Args[2]
	}

	fmt.Printf("--> Reading SnarkJS Verification Key: %s\n", inputFile)
	data, err := ioutil.ReadFile(inputFile)
	if err != nil {
		panic(fmt.Errorf("failed to read file: %w", err))
	}

	// 1. Unmarshal Circom VK
	circomVk, err := parser.UnmarshalCircomVerificationKeyJSON(data)
	if err != nil {
		panic(fmt.Errorf("failed to unmarshal JSON: %w", err))
	}

	// 2. Convert to Gnark VK
	gnarkVk, err := parser.ConvertVerificationKey(circomVk)
	if err != nil {
		panic(fmt.Errorf("failed to convert to Gnark VK: %w", err))
	}

	// 3. Write to binary
	f, err := os.Create(outputFile)
	if err != nil {
		panic(fmt.Errorf("failed to create output file: %w", err))
	}
	defer f.Close()

	if _, err := gnarkVk.WriteTo(f); err != nil {
		panic(fmt.Errorf("failed to write binary VK: %w", err))
	}

	fmt.Printf("--> Successfully converted to Gnark Binary: %s\n", outputFile)

	abs, _ := filepath.Abs(outputFile)
	fmt.Printf("    Path: %s\n", abs)
}
