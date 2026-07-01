package cmd

import (
	"github.com/dionebastos/vibesec/internal/scan"
	"github.com/spf13/cobra"
)

var reconCmd = &cobra.Command{
	Use:   "recon [target]",
	Short: "Full reconnaissance workflow (fingerprint, bundle, headers, endpoints, and more)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target, err := normalizeTarget(args[0])
		if err != nil {
			return err
		}
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		return scan.RunRecon(target, cfg, scan.ModulesFromConfig(cfg))
	},
}
