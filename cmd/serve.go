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

		service := enterprise.NewService(cfg, st)
		server := api.NewServerWithOrigins(service, cfg.Enterprise.AllowedOrigins)
		if FrontendHandler != nil {
			server.SetFrontend(FrontendHandler())
		}
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
