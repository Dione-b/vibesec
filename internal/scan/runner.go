package scan

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/dionebastos/vibesec/internal/auth"
	"github.com/dionebastos/vibesec/internal/ai"
	"github.com/dionebastos/vibesec/internal/authorization"
	"github.com/dionebastos/vibesec/internal/bundle"
	"github.com/dionebastos/vibesec/internal/burp"
	"github.com/dionebastos/vibesec/internal/config"
	"github.com/dionebastos/vibesec/internal/correlation"
	"github.com/dionebastos/vibesec/internal/endpoint"
	"github.com/dionebastos/vibesec/internal/fingerprint"
	"github.com/dionebastos/vibesec/internal/finding"
	"github.com/dionebastos/vibesec/internal/headers"
	"github.com/dionebastos/vibesec/internal/nuclei"
	"github.com/dionebastos/vibesec/internal/plugin"
	"github.com/dionebastos/vibesec/internal/recon"
	reportengine "github.com/dionebastos/vibesec/internal/report"
	"github.com/dionebastos/vibesec/internal/scanctx"
	"github.com/dionebastos/vibesec/internal/ui"
)

var errNoModules = errors.New("no modules enabled — check vibesec.yaml")

type Options struct {
	FullRecon bool
	Writer    io.Writer
	Silent    bool
}

type Result struct {
	Target        string
	Context       *scanctx.Context
	Document      *reportengine.Document
	Report        *reportengine.Output
	FindingCount  int
	HighCount     int
	CriticalCount int
	RiskLevel     string
}

func Run(target string, cfg *config.Config, modules []Module) error {
	_, err := Execute(target, cfg, modules, Options{})
	return err
}

func RunRecon(target string, cfg *config.Config, modules []Module) error {
	_, err := Execute(target, cfg, modules, Options{FullRecon: true})
	return err
}

func Execute(target string, cfg *config.Config, modules []Module, opts Options) (*Result, error) {
	if cfg == nil {
		cfg = config.Default()
	}
	if len(modules) == 0 {
		return nil, errNoModules
	}

	writer := opts.Writer
	if writer == nil && !opts.Silent {
		writer = os.Stdout
	}

	ctx, err := scanctx.New(target, cfg)
	if err != nil {
		return nil, err
	}
	ctx.ModulesRun = len(modules)

	section := "Modules"
	if opts.FullRecon {
		section = "Recon workflow"
	}

	var lines []string
	if writer != nil {
		lines = append(lines, ui.TargetBlock(target))
		lines = append(lines, ui.Section(section))
		lines = append(lines, "")
	}

	for _, mod := range modules {
		if opts.FullRecon && mod.Name == "Report" {
			reconResult, err := recon.Collect(ctx)
			if err != nil {
				return nil, fmt.Errorf("recon: %w", err)
			}
			ctx.ReconAssets = toReconAssets(reconResult)
			if writer != nil {
				lines = append(lines, ui.ModuleOK("Passive assets"))
				lines = append(lines, recon.FormatOutput(reconResult)...)
			}
		}

		findings, err := mod.Run(ctx)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", mod.Name, err)
		}
		ctx.AddFindings(findings...)
		if writer != nil {
			lines = append(lines, ui.ModuleOK(mod.Name))
			lines = append(lines, moduleOutput(mod.Name, ctx)...)
		}
	}

	summary := finding.Summarize(ctx.Findings)
	if writer != nil {
		lines = append(lines, "")
		if summary.Total > 0 {
			lines = append(lines, ui.Section("Findings"))
			lines = append(lines, "")
			lines = append(lines, "  "+summary.String())
			lines = append(lines, "")
		}
		lines = append(lines, ui.Done())
		if _, err := io.WriteString(writer, strings.Join(lines, "\n")+"\n"); err != nil {
			return nil, err
		}
	}

	doc := reportengine.Build(ctx, ctx.ModulesRun)
	var output *reportengine.Output
	if ctx.ReportMarkdown != "" || ctx.ReportJSON != "" || ctx.ReportHTML != "" {
		output = &reportengine.Output{
			Markdown: ctx.ReportMarkdown,
			JSON:     ctx.ReportJSON,
			HTML:     ctx.ReportHTML,
		}
	}

	return &Result{
		Target:        target,
		Context:       ctx,
		Document:      doc,
		Report:        output,
		FindingCount:  summary.Total,
		HighCount:     summary.High,
		CriticalCount: summary.Critical,
		RiskLevel:     doc.Risk.Level,
	}, nil
}

func moduleOutput(name string, ctx *scanctx.Context) []string {
	switch name {
	case "Fingerprint":
		return fingerprint.FormatOutput(ctx.Fingerprint)
	case "Headers":
		return headers.FormatOutput(ctx.Headers)
	case "Bundle":
		return bundle.FormatOutput(ctx.Bundle)
	case "Endpoint Discovery":
		return endpoint.FormatOutput(ctx.Endpoints)
	case "Auth Scanner":
		return auth.FormatOutput(ctx.Auth)
	case "Authorization Scanner":
		return authorization.FormatOutput(ctx.Authorization)
	case "Plugins":
		return plugin.FormatOutput(ctx.Plugins)
	case "Nuclei":
		return nuclei.FormatOutput(ctx.Nuclei)
	case "Burp":
		return burp.FormatOutput(ctx.Burp)
	case "Correlation":
		return correlation.FormatOutput(countCorrelationFindings(ctx.Findings))
	case "AI Analyzer":
		return ai.FormatOutput(ctx.AI)
	case "Report":
		return formatReportOutput(ctx.ReportMarkdown, ctx.ReportJSON, ctx.ReportHTML)
	default:
		return nil
	}
}

func formatReportOutput(markdown, jsonPath, htmlPath string) []string {
	if markdown == "" && jsonPath == "" && htmlPath == "" {
		return nil
	}
	lines := []string{""}
	if markdown != "" {
		lines = append(lines, "  "+markdown)
	}
	if jsonPath != "" {
		lines = append(lines, "  "+jsonPath)
	}
	if htmlPath != "" {
		lines = append(lines, "  "+htmlPath)
	}
	return lines
}

func toReconAssets(result *recon.Result) []scanctx.ReconAsset {
	if result == nil {
		return nil
	}
	assets := make([]scanctx.ReconAsset, len(result.Assets))
	for i, asset := range result.Assets {
		assets[i] = scanctx.ReconAsset{
			Path:    asset.Path,
			Status:  asset.Status,
			Summary: asset.Summary,
		}
	}
	return assets
}

func countCorrelationFindings(items []finding.Finding) int {
	n := 0
	for _, item := range items {
		if item.Module == finding.ModuleCorrelation {
			n++
		}
	}
	return n
}
