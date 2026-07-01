package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/dionebastos/vibesec/internal/api"
	"github.com/dionebastos/vibesec/internal/enterprise"
	"github.com/dionebastos/vibesec/internal/store"
	"github.com/dionebastos/vibesec/internal/ui"
	"github.com/spf13/cobra"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the VibeSec REST API and web dashboard",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		dsn := cfg.Enterprise.Database
		if env := os.Getenv("VIBESEC_DATABASE"); env != "" {
			dsn = env
		}

		st, err := store.Open(dsn)
		if err != nil {
			return fmt.Errorf("database: %w", err)
		}
		defer st.Close()

		users, err := st.ListUsers(context.Background())
		if err != nil {
			return err
		}
		if len(users) > 0 {
			fmt.Println(ui.Section("VibeSec API"))
			fmt.Println()
			fmt.Println("Default API key (admin):")
			fmt.Println("  " + users[0].APIKey)
			fmt.Println()
		}

		service := enterprise.NewService(cfg, st)
		server := api.NewServer(service)
		listen := cfg.Enterprise.APIListen
		if listen == "" {
			listen = ":8080"
		}

		scheduler := enterprise.NewScheduler(service, 0)
		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer cancel()
		go scheduler.Run(ctx)

		fmt.Printf("Listening on http://localhost%s\n", listen)
		fmt.Println("Dashboard: /")
		return api.ListenAndServe(ctx, listen, server.Handler())
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
}
