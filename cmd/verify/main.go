package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Stygian-Inc/ptx-jesuit-go/pkg/ptxloader"
	"github.com/Stygian-Inc/ptx-jesuit-go/pkg/verifier"
	"github.com/Stygian-Inc/ptx-jesuit-go/pkg/vk"
	"github.com/fatih/color"
	"github.com/vocdoni/circom2gnark/parser"
)

func main() {
	opts := parseArgs()
	if opts.FilePath == "" {
		fmt.Println("Usage: verify <file.ptx> [-v] [--intended-scope x,y] [--intended-audience a,b] [--strict] [--redis-url url] [--time-dev] [--time-skip-dev]")
		os.Exit(1)
	}

	// Time-skip-dev
	if opts.TimeSkipDev {
		ptxFile, err := ptxloader.LoadPTX(opts.FilePath)
		if err != nil {
			fmt.Println("0")
			os.Exit(1)
		}

		proof := ptxFile.GetProof()
		// Extract wrapper
		var wrapper struct {
			PublicSignals []string        `json:"publicSignals"`
			Proof         json.RawMessage `json:"proof"`
		}
		if err := json.Unmarshal(proof.ProofData, &wrapper); err != nil {
			fmt.Println("0")
			os.Exit(1)
		}

		// Parse Proof with circom2gnark
		circomProof, err := parser.UnmarshalCircomProofJSON(wrapper.Proof)
		if err != nil {
			fmt.Println("0")
			os.Exit(1)
		}

		circomVk, err := vk.LoadCircomKey("verification_key.json")
		if err != nil {
			fmt.Println("0")
			os.Exit(1)
		}

		// Convert to GnarkProof
		gnarkProof, err := parser.ConvertCircomToGnark(circomProof, circomVk, wrapper.PublicSignals)
		if err != nil {
			fmt.Println("0")
			os.Exit(1)
		}

		start := time.Now()
		valid, err := parser.VerifyProof(gnarkProof)
		elapsed := time.Since(start).Seconds()

		fmt.Printf("%.5f\n", 0.0) // DNS Time (Skipped)
		fmt.Printf("%.5f\n", elapsed)
		if valid && err == nil {
			fmt.Println("1")
			os.Exit(0)
		} else {
			fmt.Println("0")
			os.Exit(1)
		}
	}

	v := verifier.NewPTXVerifier(opts.VerificationOptions)

	// CLI Output similar to JS
	if !opts.TimeDev {
		printHeader("PTX Verification Tool")
		fmt.Printf("%s  Reading: %s\n", color.BlueString("ℹ"), opts.FilePath)
	}

	res, err := v.Verify()
	if err != nil {
		printError(err.Error())
		os.Exit(1)
	}

	if !opts.TimeDev {
		// 1. PTX Header
		printSection("1. PTX Header")
		printSuccess("Header validated")

		for _, e := range res.Errors {
			printError(e)
		}

		// DNS
		printSection("3. DNS Anchor")
		if res.Dns.Valid {
			printSuccess("DNS anchor verified")
		} else {
			printError(res.Dns.Error)
		}

		// ZK
		printSection("4. ZK-SNARK")
		if res.Zk.Skipped {
			fmt.Printf("%s  Skipped (not Groth16)\n", color.BlueString("ℹ"))
		} else if res.Zk.Valid {
			printSuccess("Proof valid")
		} else {
			printError("Proof invalid (Check verbose for details)")
			if opts.Verbose && res.Zk.Error != "" {
				fmt.Printf("   Reason: %s\n", res.Zk.Error)
			}
		}

		// Success
		if res.Success {
			printHeader("Verification Successful")
			color.New(color.BgBlue, color.FgWhite).Printf("   ALL CHECKS PASSED   \n")
		}
	}

	// Time-dev output
	if opts.TimeDev {
		fmt.Printf("%.4f\n", res.Dns.FetchTimeMs/1000)
		if res.Zk.ProofTimeMs > 0 {
			fmt.Printf("%.4f\n", res.Zk.ProofTimeMs/1000)
		} else {
			fmt.Printf("0.0000\n")
		}
		if res.Success {
			fmt.Println("1")
		} else {
			fmt.Println("0")
		}
	}

	if res.Success {
		os.Exit(0)
	} else {
		os.Exit(1)
	}
}

type Options struct {
	verifier.VerificationOptions
	TimeDev     bool
	TimeSkipDev bool
}

func parseArgs() Options {
	args := os.Args[1:]
	opts := Options{}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--intended-scope" && i+1 < len(args) {
			opts.IntendedScope = strings.Split(args[i+1], ",")
			for j := range opts.IntendedScope {
				opts.IntendedScope[j] = strings.TrimSpace(opts.IntendedScope[j])
			}
			i++
		} else if arg == "--intended-audience" && i+1 < len(args) {
			opts.IntendedAudience = strings.Split(args[i+1], ",")
			for j := range opts.IntendedAudience {
				opts.IntendedAudience[j] = strings.TrimSpace(opts.IntendedAudience[j])
			}
			i++
		} else if arg == "--strict" {
			opts.StrictMode = true
		} else if arg == "--redis-url" && i+1 < len(args) {
			opts.RedisURL = args[i+1]
			i++
		} else if arg == "-v" || arg == "--verbose" {
			opts.Verbose = true
		} else if arg == "--time-dev" {
			opts.TimeDev = true
		} else if arg == "--time-skip-dev" {
			opts.TimeSkipDev = true
		} else if !strings.HasPrefix(arg, "-") {
			opts.FilePath = arg
		}
	}
	return opts
}

func printHeader(msg string) {
	cyan := color.New(color.FgCyan).SprintFunc()
	fmt.Printf("\n%s\n%s%s\n%s\n",
		cyan(strings.Repeat("=", 64)),
		strings.Repeat(" ", (64-len(msg))/2), msg,
		cyan(strings.Repeat("=", 64)))
}

func printSection(msg string) {
	blue := color.New(color.FgBlue).SprintFunc()
	fmt.Printf("\n%s %s %s\n",
		blue(strings.Repeat("=", (64-len(msg)-2)/2)),
		msg,
		blue(strings.Repeat("=", (64-len(msg)-2)/2)))
}

func printSuccess(msg string) {
	fmt.Printf("%s✔  %s\n", color.GreenString(""), msg)
}

func printError(msg string) {
	fmt.Printf("%s✖  [ERROR] %s\n", color.RedString(""), msg)
}
