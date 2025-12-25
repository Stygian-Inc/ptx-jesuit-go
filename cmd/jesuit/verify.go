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
	"github.com/spf13/cobra"
	"github.com/vocdoni/circom2gnark/parser"
)

var (
	intendedScope    []string
	intendedAudience []string
	strictMode       bool
	redisURL         string
	timeDev          bool
	timeSkipDev      bool
)

var verifyCmd = &cobra.Command{
	Use:   "verify <file.ptx>",
	Short: "Verify a PTX proof",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		filePath := args[0]

		opts := verifier.VerificationOptions{
			FilePath:         filePath,
			IntendedScope:    intendedScope,
			IntendedAudience: intendedAudience,
			StrictMode:       strictMode,
			RedisURL:         redisURL,
			Verbose:          verbose,
		}

		if timeSkipDev {
			runTimeSkipDev(filePath)
			return
		}

		v := verifier.NewPTXVerifier(opts)

		// CLI Output similar to JS
		if !timeDev {
			printHeader("PTX Verification Tool")
			fmt.Printf("%s  Reading: %s\n", color.BlueString("ℹ"), filePath)
		}

		res, err := v.Verify()
		if err != nil {
			printError(err.Error())
			os.Exit(1)
		}

		if !timeDev {
			// Print Results
			printSection("1. PTX Header")
			printSuccess("Header validated")

			for _, e := range res.Errors {
				printError(e)
			}

			printSection("3. DNS Anchor")
			if res.Dns.Valid {
				printSuccess("DNS anchor verified")
			} else {
				printError(res.Dns.Error)
			}

			printSection("4. ZK-SNARK")
			if res.Zk.Skipped {
				fmt.Printf("%s  Skipped (not Groth16)\n", color.BlueString("ℹ"))
			} else if res.Zk.Valid {
				printSuccess("Proof valid")
			} else {
				printError("Proof invalid (Check verbose for details)")
				if verbose && res.Zk.Error != "" {
					fmt.Printf("   Reason: %s\n", res.Zk.Error)
				}
			}

			if res.Success {
				printHeader("Verification Successful")
				color.New(color.BgBlue, color.FgWhite).Printf("   ALL CHECKS PASSED   \n")
			}
		}

		// Time-dev output
		if timeDev {
			fmt.Printf("%.4f\n", res.Dns.FetchTimeMs/1000)
			if res.Zk.ProofTimeMs > 0 {
				fmt.Printf("%.4f\n", res.Zk.ProofTimeMs/1000)
			} else {
				fmt.Printf("%.4f\n", 0.0)
			}
			if res.Success {
				fmt.Println("1")
			} else {
				fmt.Println("0")
			}
		}

		if !res.Success {
			os.Exit(1)
		}
	},
}

func runTimeSkipDev(filePath string) {
	ptxFile, err := ptxloader.LoadPTX(filePath)
	if err != nil {
		fmt.Println("0")
		os.Exit(1)
	}

	proof := ptxFile.GetProof()
	var wrapper struct {
		PublicSignals []string        `json:"publicSignals"`
		Proof         json.RawMessage `json:"proof"`
	}
	if err := json.Unmarshal(proof.ProofData, &wrapper); err != nil {
		fmt.Println("0")
		os.Exit(1)
	}

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

func init() {
	verifyCmd.Flags().StringSliceVar(&intendedScope, "intended-scope", nil, "intended scope")
	verifyCmd.Flags().StringSliceVar(&intendedAudience, "intended-audience", nil, "intended audience")
	verifyCmd.Flags().BoolVar(&strictMode, "strict", false, "enable strict mode")
	verifyCmd.Flags().StringVar(&redisURL, "redis-url", "", "redis url for caching")
	verifyCmd.Flags().BoolVar(&timeDev, "time-dev", false, "output only time and status")
	verifyCmd.Flags().BoolVar(&timeSkipDev, "time-skip-dev", false, "skip semantic checks, output time and status")
	rootCmd.AddCommand(verifyCmd)
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
