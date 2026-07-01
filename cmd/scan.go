package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"

	"github.com/dionebastos/vibesec/internal/scan"
	"github.com/spf13/cobra"
)

var (
	scanCI         bool
	scanJSONOutput bool
	scanSave       bool
)

var scanCmd = &cobra.Command{
	Use:   "scan [target]",
	Short: "Run security modules against a target URL",
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
		if scanSave {
			cfg.Enterprise.PersistScans = true
		}

		modules := scan.ModulesFromConfig(cfg)
		opts := scan.Options{Silent: scanJSONOutput}
		result, err := scan.Execute(target, cfg, modules, opts)
		if err != nil {
			return err
		}

		payload := scanRunnerResult{Result: result}
		if result.Document != nil {
			docJSON, marshalErr := json.Marshal(result.Document)
			if marshalErr != nil {
				return marshalErr
			}
			payload.DocumentJSON = string(docJSON)
		}

		if scanJSONOutput {
			if err := json.NewEncoder(os.Stdout).Encode(ciSummaryFromResult(payload)); err != nil {
				return err
			}
		}

		if err := persistScanIfEnabled(cfg, &payload); err != nil {
			return err
		}

		if scanCI && (result.CriticalCount > 0 || result.HighCount > 0) {
			return fmt.Errorf("CI gate failed: %d critical, %d high findings", result.CriticalCount, result.HighCount)
		}
		return nil
	},
}

type scanRunnerResult struct {
	Result       *scan.Result
	DocumentJSON string
}

type ciSummary struct {
	Target        string `json:"target"`
	RiskLevel     string `json:"risk_level"`
	FindingCount  int    `json:"finding_count"`
	HighCount     int    `json:"high_count"`
	CriticalCount int    `json:"critical_count"`
	ReportHTML    string `json:"report_html,omitempty"`
	ReportJSON    string `json:"report_json,omitempty"`
}

func ciSummaryFromResult(payload scanRunnerResult) ciSummary {
	out := ciSummary{
		Target:        payload.Result.Target,
		RiskLevel:     payload.Result.RiskLevel,
		FindingCount:  payload.Result.FindingCount,
		HighCount:     payload.Result.HighCount,
		CriticalCount: payload.Result.CriticalCount,
	}
	if payload.Result.Report != nil {
		out.ReportHTML = payload.Result.Report.HTML
		out.ReportJSON = payload.Result.Report.JSON
	}
	return out
}

func init() {
	scanCmd.Flags().StringVar(&burpFile, "burp-file", "", "Burp Suite issues XML export to import")
	scanCmd.Flags().BoolVar(&scanCI, "ci", false, "Exit with error when critical or high findings are present")
	scanCmd.Flags().BoolVar(&scanJSONOutput, "json", false, "Print CI-friendly JSON summary to stdout")
	scanCmd.Flags().BoolVar(&scanSave, "save", false, "Persist scan results to the enterprise database")
}

func normalizeTarget(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid target URL: %w", err)
	}
	if parsed.Scheme == "" {
		parsed, err = url.Parse("https://" + raw)
		if err != nil {
			return "", fmt.Errorf("invalid target URL: %w", err)
		}
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("target must include a hostname")
	}
	return parsed.String(), nil
}
