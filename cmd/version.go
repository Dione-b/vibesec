package cmd

import (
	"fmt"
	"runtime"

	"github.com/dionebastos/vibesec/internal/ui"
	"github.com/spf13/cobra"
)

var (
	version = "0.1.0-dev"
	commit  = "dev"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("%s %s (%s)\n", ui.Section("vibesec"), version, commit)
		fmt.Printf("go %s %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
	},
}
