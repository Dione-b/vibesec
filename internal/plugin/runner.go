package plugin

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"time"

	"github.com/dionebastos/vibesec/internal/config"
)

type Runner struct {
	executor *Executor
	cfg      *config.PluginsConfig
}

func NewRunner(cfg *config.Config) *Runner {
	timeout := 60 * time.Second
	if cfg != nil && cfg.Timeout > 0 {
		timeout = time.Duration(cfg.Timeout) * time.Second
	}
	return &Runner{
		executor: NewExecutor(timeout),
		cfg:      pluginsConfig(cfg),
	}
}

func pluginsConfig(cfg *config.Config) *config.PluginsConfig {
	if cfg == nil {
		def := config.Default()
		return &def.Plugins
	}
	return &cfg.Plugins
}

func (r *Runner) RunAll(ctx context.Context, target string) *Collection {
	if r.cfg == nil || !r.cfg.Enabled {
		return &Collection{}
	}

	host := hostname(target)
	collection := &Collection{}
	runners := []func(context.Context, string, string) Result{
		r.runHttpx,
		r.runNmap,
		r.runKatana,
		r.runSubfinder,
		r.runNaabu,
		r.runDnsx,
	}
	for _, run := range runners {
		result := run(ctx, target, host)
		collection.Results = append(collection.Results, result)
	}
	return collection
}

func hostname(target string) string {
	parsed, err := url.Parse(target)
	if err != nil || parsed.Hostname() == "" {
		return strings.TrimPrefix(strings.TrimPrefix(target, "https://"), "http://")
	}
	return parsed.Hostname()
}

func skipped(name string) Result {
	return Result{Name: name, Status: StatusSkipped, Summary: "binary not found in PATH"}
}

func withRaw(result Result, raw []byte) Result {
	if len(raw) > 0 {
		result.Raw = json.RawMessage(raw)
	}
	return result
}
