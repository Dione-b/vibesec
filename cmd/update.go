package cmd

import (
	"fmt"

	"github.com/dionebastos/vibesec/internal/ui"
	"github.com/spf13/cobra"
)

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update vibesec to the latest release",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println(ui.Section("Update"))
		fmt.Println()
		fmt.Println(ui.Muted("Self-update will be available in a future release."))
		return nil
	},
}
