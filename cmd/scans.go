package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/dionebastos/vibesec/internal/config"
	"github.com/dionebastos/vibesec/internal/enterprise"
	"github.com/dionebastos/vibesec/internal/store"
	"github.com/dionebastos/vibesec/internal/ui"
	"github.com/spf13/cobra"
)

var scansCmd = &cobra.Command{
	Use:   "scans",
	Short: "Manage stored scan history",
}

var scansListCmd = &cobra.Command{
	Use:   "list",
	Short: "List scans from the database",
	RunE: func(cmd *cobra.Command, args []string) error {
		st, err := openStore()
		if err != nil {
			return err
		}
		defer st.Close()

		items, err := st.ListScans(context.Background(), 20)
		if err != nil {
			return err
		}
		fmt.Println(ui.Section("Scan history"))
		fmt.Println()
		if len(items) == 0 {
			fmt.Println(ui.Muted("  no scans stored"))
			return nil
		}
		for _, item := range items {
			fmt.Printf("  %s  %s  %s  findings=%d  risk=%s\n",
				item.ID, item.Status, item.Target, item.FindingCount, item.RiskLevel)
		}
		return nil
	},
}

var userCmd = &cobra.Command{
	Use:   "user",
	Short: "Manage API users",
}

var userCreateCmd = &cobra.Command{
	Use:   "create [name]",
	Short: "Create a new API user",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		st, err := openStore()
		if err != nil {
			return err
		}
		defer st.Close()

		user, err := st.CreateUser(context.Background(), args[0], store.NewAPIKey())
		if err != nil {
			return err
		}
		fmt.Println(ui.Section("API user created"))
		fmt.Println()
		fmt.Printf("Name: %s\n", user.Name)
		fmt.Printf("API key: %s\n", user.APIKey)
		return nil
	},
}

func openStore() (*store.Store, error) {
	cfg, err := loadConfig()
	if err != nil {
		return nil, err
	}
	dsn := cfg.Enterprise.Database
	if env := os.Getenv("VIBESEC_DATABASE"); env != "" {
		dsn = env
	}
	return store.Open(dsn)
}

func persistScanIfEnabled(cfg *config.Config, result *scanRunnerResult) error {
	if result == nil || cfg == nil || !cfg.Enterprise.PersistScans {
		return nil
	}
	st, err := openStore()
	if err != nil {
		return err
	}
	defer st.Close()

	users, err := st.ListUsers(context.Background())
	if err != nil {
		return err
	}
	if len(users) == 0 {
		return fmt.Errorf("no API users in database")
	}
	service := enterprise.NewService(cfg, st)
	_, err = service.SaveCompletedScan(context.Background(), users[0].ID, result.Result, result.DocumentJSON)
	return err
}

func init() {
	rootCmd.AddCommand(scansCmd)
	scansCmd.AddCommand(scansListCmd)
	rootCmd.AddCommand(userCmd)
	userCmd.AddCommand(userCreateCmd)
}
