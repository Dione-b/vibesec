package cmd

import (
	"fmt"
	"os"

	reportengine "github.com/dionebastos/vibesec/internal/report"
	"github.com/dionebastos/vibesec/internal/ui"
	"github.com/spf13/cobra"
)

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Show paths for the latest generated report",
	RunE: func(cmd *cobra.Command, args []string) error {
		latest, err := reportengine.LoadLatest("")
		if err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("no reports found — run `vibesec scan <target>` first")
			}
			return err
		}

		fmt.Println(ui.Section("Report"))
		fmt.Println()
		fmt.Printf("Target: %s\n", latest.Target)
		fmt.Printf("Generated: %s\n\n", latest.Generated.Format("2006-01-02 15:04:05 UTC"))
		if latest.Markdown != "" {
			fmt.Println(latest.Markdown)
		}
		if latest.JSON != "" {
			fmt.Println(latest.JSON)
		}
		if latest.HTML != "" {
			fmt.Println(latest.HTML)
		}
		return nil
	},
}
