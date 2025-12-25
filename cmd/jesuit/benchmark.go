package main

import (
	"bytes"
	"fmt"
	"math"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

var (
	numRuns    int
	executable string
)

var benchmarkCmd = &cobra.Command{
	Use:   "benchmark <file.ptx>",
	Short: "Benchmark PTX verification",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		proofFile := args[0]

		if executable == "" {
			executable = "./verify"
		}

		// Check if executable exists, if not fallback to self for convenience if needed,
		// but the user specifically asked for ./verify
		if _, err := os.Stat(executable); os.IsNotExist(err) && executable == "./verify" {
			// If ./verify doesn't exist, we might want to warn or fallback.
			// But the user's instructions were specific.
			// I'll stick to ./verify but maybe add a check.
		}

		// --- Run Full Verification Benchmark ---
		fullArgs := []string{proofFile, "--time-dev"}
		runBenchmark("Full Verification", executable, fullArgs, numRuns)

		// --- Run ZK-Only Verification Benchmark ---
		zkArgs := []string{proofFile, "--time-skip-dev"}
		runBenchmark("ZK-Only (Raw Proof)", executable, zkArgs, numRuns)
	},
}

func runBenchmark(mode, exe string, args []string, n int) {
	var dnsTimes []float64
	var proofTimes []float64
	var totalTimes []float64
	var statuses []int

	fmt.Printf("\nRunning benchmark for: %s %s\n", exe, strings.Join(args, " "))

	for i := 0; i < n; i++ {
		fmt.Printf("\r  Run %d/%d...", i+1, n)

		cmd := exec.Command(exe, args...)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		err := cmd.Run()
		if err != nil && cmd.ProcessState.ExitCode() == 0 {
			// This shouldn't happen if err != nil
		}

		output := strings.TrimSpace(stdout.String())
		lines := strings.Split(output, "\n")

		if len(lines) < 3 {
			fmt.Printf("\n[WARN] Run %d produced insufficient output. Skipping.\n", i+1)
			if stderr.Len() > 0 {
				fmt.Printf("Stderr: %s\n", stderr.String())
			}
			continue
		}

		dnsTimeStr := lines[len(lines)-3]
		proofTimeStr := lines[len(lines)-2]
		statusStr := lines[len(lines)-1]

		dt, errD := strconv.ParseFloat(strings.TrimSpace(dnsTimeStr), 64)
		pt, errP := strconv.ParseFloat(strings.TrimSpace(proofTimeStr), 64)
		s, errS := strconv.Atoi(strings.TrimSpace(statusStr))

		if errD != nil || errP != nil || errS != nil {
			fmt.Printf("\n[ERROR] Failed to parse output on run %d\n", i+1)
			continue
		}

		dnsTimes = append(dnsTimes, dt)
		proofTimes = append(proofTimes, pt)
		totalTimes = append(totalTimes, dt+pt)
		statuses = append(statuses, s)
	}

	fmt.Printf("\r%-40s\r", "")
	fmt.Println("Benchmark complete.")

	printStats(mode, dnsTimes, proofTimes, totalTimes, statuses, n)
}

func printStats(mode string, dnsTimes, proofTimes, totalTimes []float64, statuses []int, totalRuns int) {
	fmt.Printf("\n--- Statistics for '%s' Mode ---\n", mode)

	if len(proofTimes) == 0 {
		fmt.Println("ERROR: No successful runs were recorded. Cannot compute statistics.")
		return
	}

	successes := 0
	for _, s := range statuses {
		if s == 1 {
			successes++
		}
	}

	fmt.Printf("Total Attempts:     %d\n", totalRuns)
	fmt.Printf("Successful Parses:  %d\n", len(proofTimes))
	fmt.Printf("  - Valid Proofs:   %d\n", successes)
	fmt.Printf("  - Invalid Proofs: %d\n", len(proofTimes)-successes)

	fmt.Println("\n--- Performance (in seconds) ---")

	// DNS Stats
	printMetricStats("DNS Fetch", dnsTimes)
	// Proof Stats
	printMetricStats("Proof Verification", proofTimes)
	// Total Stats
	printMetricStats("Total Time", totalTimes)

	fmt.Printf("--------------------------------------\n")
}

func printMetricStats(label string, times []float64) {
	if len(times) == 0 {
		return
	}

	var mean, stdev, minTime, maxTime float64
	minTime = times[0]
	maxTime = times[0]
	sum := 0.0

	for _, t := range times {
		sum += t
		if t < minTime {
			minTime = t
		}
		if t > maxTime {
			maxTime = t
		}
	}
	mean = sum / float64(len(times))

	if len(times) > 1 {
		var sqDiffSum float64
		for _, t := range times {
			sqDiffSum += math.Pow(t-mean, 2)
		}
		stdev = math.Sqrt(sqDiffSum / float64(len(times)-1))
	}

	fmt.Printf("[%s]\n", label)
	fmt.Printf("  Average:            %.6f s\n", mean)
	fmt.Printf("  Standard Deviation: %.6f s\n", stdev)
	fmt.Printf("  Min Time:           %.6f s\n", minTime)
	fmt.Printf("  Max Time:           %.6f s\n", maxTime)
}

func init() {
	benchmarkCmd.Flags().IntVarP(&numRuns, "num-runs", "n", 10, "number of times to run the verifier")
	benchmarkCmd.Flags().StringVarP(&executable, "executable", "e", "", "path to the verifier executable (default: self)")
	rootCmd.AddCommand(benchmarkCmd)
}
