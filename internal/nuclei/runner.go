package nuclei

import (
	"context"
	"fmt"
	"time"

	"github.com/dionebastos/vibesec/internal/config"
	"github.com/dionebastos/vibesec/internal/plugin"
)

type Runner struct {
	exec *plugin.Executor
	cfg  *config.NucleiConfig
}

func NewRunner(cfg *config.Config) *Runner {
	timeout := 120 * time.Second
	if cfg != nil && cfg.Timeout > 0 {
		timeout = time.Duration(cfg.Timeout*3) * time.Second
	}
	nucleiCfg := &config.NucleiConfig{}
	if cfg != nil {
		nucleiCfg = &cfg.Nuclei
	}
	return &Runner{
		exec: plugin.NewExecutor(timeout),
		cfg:  nucleiCfg,
	}
}

func (r *Runner) Run(ctx context.Context, target string) *Result {
	if r.cfg == nil || !r.cfg.Enabled {
		return &Result{Status: StatusSkipped, Summary: "disabled in config"}
	}
	if !r.exec.Available("nuclei") {
		return &Result{Status: StatusSkipped, Summary: "nuclei not found in PATH"}
	}

	args := []string{
		"-u", target,
		"-jsonl",
		"-silent",
		"-no-color",
	}
	if len(r.cfg.Severity) > 0 {
		args = append(args, "-severity", stringsJoin(r.cfg.Severity))
	}
	if r.cfg.RateLimit > 0 {
		args = append(args, "-rate-limit", fmt.Sprintf("%d", r.cfg.RateLimit))
	}

	raw, err := r.exec.Run(ctx, "nuclei", args...)
	result := &Result{}
	if err != nil {
		result.Status = StatusError
		result.Error = err.Error()
		result.Summary = "scan failed"
		return result
	}

	result.Findings = ParseJSONL(raw)
	result.Status = StatusOK
	result.Summary = fmt.Sprintf("%d template matches", len(result.Findings))
	return result
}

func stringsJoin(items []string) string {
	if len(items) == 0 {
		return ""
	}
	out := items[0]
	for i := 1; i < len(items); i++ {
		out += "," + items[i]
	}
	return out
}
