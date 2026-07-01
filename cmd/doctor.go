package cmd

import (
	"fmt"
	"os/exec"
	"runtime"

	"github.com/dionebastos/vibesec/internal/ui"
	"github.com/spf13/cobra"
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check environment and external tool dependencies",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println(ui.Section("Doctor"))
		fmt.Println()

		checks := []struct {
			name string
			ok   bool
			note string
		}{
			{name: "Go runtime", ok: true, note: runtime.Version()},
		}

		for _, tool := range []string{"nmap", "httpx", "nuclei", "katana", "subfinder", "naabu", "dnsx"} {
			path, err := exec.LookPath(tool)
			checks = append(checks, struct {
				name string
				ok   bool
				note string
			}{
				name: tool,
				ok:   err == nil,
				note: path,
			})
		}

		if st, err := openStore(); err == nil {
			checks = append(checks, struct {
				name string
				ok   bool
				note string
			}{name: "Enterprise database", ok: true, note: "connected"})
			_ = st.Close()
		} else {
			checks = append(checks, struct {
				name string
				ok   bool
				note string
			}{name: "Enterprise database", ok: false, note: err.Error()})
		}

		for _, c := range checks {
			if c.ok {
				fmt.Println(ui.ModuleOK(c.name))
				if c.note != "" {
					fmt.Println(ui.Muted("  " + c.note))
				}
				continue
			}
			fmt.Println(ui.Warn(c.name + " not found"))
			if c.note != "" {
				fmt.Println(ui.Muted("  " + c.note))
			}
		}

		return nil
	},
}
