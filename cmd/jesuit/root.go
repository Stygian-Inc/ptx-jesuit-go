package main

import (
	"os"

	"github.com/spf13/cobra"
)

var verbose bool

var rootCmd = &cobra.Command{
	Use:   "jesuit",
	Short: "Jesuit is a PTX verification and benchmarking tool",
	Long:  `A fast and efficient CLI tool for verifying PTX proofs and benchmarking the verification process.`,
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose output")
}
