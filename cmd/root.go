package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "vibesec",
	Short: "Security reconnaissance and scanning for web applications",
	Long:  "VibeSec is a CLI security scanner focused on fingerprinting, headers, bundles, and endpoint discovery.",
	RunE: func(cmd *cobra.Command, args []string) error {
		return cmd.Help()
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&configPath, "config", "", "config file (default: ./vibesec.yaml or ~/.config/vibesec/vibesec.yaml)")

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(reconCmd)
	rootCmd.AddCommand(reportCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(doctorCmd)
	rootCmd.AddCommand(updateCmd)
}
