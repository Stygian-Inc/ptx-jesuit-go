package main

import (
	"fmt"
	"math"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Stygian-Inc/ptx-jesuit-go/pkg/crypto"
	"github.com/Stygian-Inc/ptx-jesuit-go/pkg/prover"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	benchTarget string
	benchRange  string
	benchRuns   int
	benchOutput string
	benchStats  bool
)

var variatedBenchmarkCmd = &cobra.Command{
	Use:   "variated-benchmark",
	Short: "Run comprehensive benchmarks varying input parameters",
	Long: `Run comprehensive benchmarks by varying specific parameters over a specified range.
	
Available targets:
  - fqdn: Vary FQDN string length (tests SHA256 hashing overhead)
  - metadata: Vary metadata JSON size (tests SHA256 hashing overhead)
  - trust-method: Test different trust method values (1=DOH, 2=GIST, etc.)
  
Reports Circuit Compilation, Witness Generation, and Proof Generation times with statistical analysis.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Parse range "min,max,step"
		parts := strings.Split(benchRange, ",")
		if len(parts) < 2 {
			color.Red("Error: --range must be 'min,max' or 'min,max,step'")
			os.Exit(1)
		}
		min, err := strconv.Atoi(parts[0])
		if err != nil {
			color.Red("Error parsing min range: %v", err)
			os.Exit(1)
		}
		max, err := strconv.Atoi(parts[1])
		if err != nil {
			color.Red("Error parsing max range: %v", err)
			os.Exit(1)
		}
		step := 1
		if len(parts) > 2 {
			step, err = strconv.Atoi(parts[2])
			if err != nil {
				color.Red("Error parsing step: %v", err)
				os.Exit(1)
			}
		}

		if step <= 0 {
			color.Red("Error: step must be positive")
			os.Exit(1)
		}

		// Print header
		color.Cyan("\n╔════════════════════════════════════════════════════════════╗")
		color.Cyan("║         Comprehensive Prover Benchmark Suite              ║")
		color.Cyan("╚════════════════════════════════════════════════════════════╝\n")

		fmt.Printf("  Target:        %s\n", color.YellowString(benchTarget))
		fmt.Printf("  Range:         %s\n", color.YellowString("%d to %d (step %d)", min, max, step))
		fmt.Printf("  Runs/step:     %s\n", color.YellowString("%d", benchRuns))
		fmt.Printf("  Statistics:    %s\n\n", color.YellowString("%t", benchStats))

		// Setup Output
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		if benchOutput == "csv" {
			if benchStats {
				fmt.Println("Value,Compile_Avg,Compile_Min,Compile_Max,Compile_StdDev,Witness_Avg,Witness_Min,Witness_Max,Witness_StdDev,Prove_Avg,Prove_Min,Prove_Max,Prove_StdDev,Total_Avg")
			} else {
				fmt.Println("Value,Compile(ms),Witness(ms),Prove(ms),Total(ms)")
			}
		} else {
			if benchStats {
				fmt.Fprintln(w, "Value\tCompile (Avg±σ)\tWitness (Avg±σ)\tProve (Avg±σ)\tTotal")
			} else {
				fmt.Fprintln(w, "Value\tCompile\tWitness\tProve\tTotal")
			}
			fmt.Fprintln(w, strings.Repeat("─", 80))
		}

		p := prover.NewProver()

		// Base params
		nullifierBig, _ := crypto.GenerateSecureRandomBigInt()
		secretBig, _ := crypto.GenerateSecureRandomBigInt()
		nullifier := nullifierBig.String()
		secret := secretBig.String()

		// Seed random
		rand.Seed(time.Now().UnixNano())

		totalSteps := (max-min)/step + 1
		currentStep := 0

		for l := min; l <= max; l += step {
			currentStep++

			// Progress indicator
			if benchOutput != "csv" {
				fmt.Fprintf(os.Stderr, "\r%s Processing step %d/%d...",
					color.BlueString("⏳"), currentStep, totalSteps)
			}

			var compileResults, witnessResults, proveResults []float64

			for r := 0; r < benchRuns; r++ {
				// Generate Inputs based on target
				domain := "example.com"
				metadata := make(map[string]interface{})
				trustMethod := 1

				switch benchTarget {
				case "fqdn":
					domain = randomString(l) + ".com"
				case "metadata":
					metadata["benchmark_data"] = randomString(l)
				case "trust-method":
					trustMethod = l
				default:
					color.Red("Unknown target: %s", benchTarget)
					os.Exit(1)
				}

				inputs, err := p.GenerateCircuitInputs(domain, metadata, nullifier, secret, trustMethod)
				if err != nil {
					color.Red("\nError generating inputs: %v", err)
					os.Exit(1)
				}

				res, _, err := p.BenchmarkNative(inputs)
				if err != nil {
					color.Red("\nError benchmarking value %d run %d: %v", l, r, err)
					os.Exit(1)
				}

				compileResults = append(compileResults, res.CompileTimeMs)
				witnessResults = append(witnessResults, res.WitnessTimeMs)
				proveResults = append(proveResults, res.ProveTimeMs)
			}

			// Calculate Statistics
			compileAvg, compileMin, compileMax, compileStdDev := calcStats(compileResults)
			witnessAvg, witnessMin, witnessMax, witnessStdDev := calcStats(witnessResults)
			proveAvg, proveMin, proveMax, proveStdDev := calcStats(proveResults)
			totalAvg := compileAvg + witnessAvg + proveAvg

			if benchOutput == "csv" {
				if benchStats {
					fmt.Printf("%d,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f\n",
						l, compileAvg, compileMin, compileMax, compileStdDev,
						witnessAvg, witnessMin, witnessMax, witnessStdDev,
						proveAvg, proveMin, proveMax, proveStdDev, totalAvg)
				} else {
					fmt.Printf("%d,%.2f,%.2f,%.2f,%.2f\n", l, compileAvg, witnessAvg, proveAvg, totalAvg)
				}
			} else {
				if benchStats {
					fmt.Fprintf(w, "%d\t%.2f±%.2f\t%.2f±%.2f\t%.2f±%.2f\t%.2f ms\n",
						l, compileAvg, compileStdDev, witnessAvg, witnessStdDev,
						proveAvg, proveStdDev, totalAvg)
				} else {
					fmt.Fprintf(w, "%d\t%.2f ms\t%.2f ms\t%.2f ms\t%.2f ms\n",
						l, compileAvg, witnessAvg, proveAvg, totalAvg)
				}
			}
			w.Flush()
		}

		if benchOutput != "csv" {
			fmt.Fprintf(os.Stderr, "\r%s Benchmark complete!%s\n",
				color.GreenString("✓"), strings.Repeat(" ", 30))
		}
	},
}

func init() {
	rootCmd.AddCommand(variatedBenchmarkCmd)
	variatedBenchmarkCmd.Flags().StringVar(&benchTarget, "target", "fqdn",
		"Parameter to vary: 'fqdn', 'metadata', or 'trust-method'")
	variatedBenchmarkCmd.Flags().StringVar(&benchRange, "range", "5,50,5",
		"Range as 'min,max' or 'min,max,step'")
	variatedBenchmarkCmd.Flags().IntVar(&benchRuns, "runs", 5,
		"Number of runs per step for averaging")
	variatedBenchmarkCmd.Flags().StringVar(&benchOutput, "output", "table",
		"Output format: 'table' or 'csv'")
	variatedBenchmarkCmd.Flags().BoolVar(&benchStats, "stats", false,
		"Include min/max/stddev statistics")
}

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func randomString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

func calcStats(values []float64) (avg, min, max, stddev float64) {
	if len(values) == 0 {
		return 0, 0, 0, 0
	}

	sum := 0.0
	min = values[0]
	max = values[0]

	for _, v := range values {
		sum += v
		if v < min {
			min = v
		}
		if v > max {
			max = v
		}
	}

	avg = sum / float64(len(values))

	// Calculate standard deviation
	variance := 0.0
	for _, v := range values {
		variance += math.Pow(v-avg, 2)
	}
	variance /= float64(len(values))
	stddev = math.Sqrt(variance)

	return avg, min, max, stddev
}
