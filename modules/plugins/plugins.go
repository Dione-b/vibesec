package plugins

import (
	"context"

	"github.com/dionebastos/vibesec/internal/finding"
	"github.com/dionebastos/vibesec/internal/plugin"
	"github.com/dionebastos/vibesec/internal/scanctx"
)

func Run(ctx *scanctx.Context) ([]finding.Finding, error) {
	runner := plugin.NewRunner(ctx.Config)
	collection := runner.RunAll(context.Background(), ctx.Target)
	ctx.Plugins = collection

	var items []finding.PluginItem
	for _, result := range collection.Results {
		items = append(items, finding.PluginItem{
			Name:      result.Name,
			Status:    result.Status,
			Summary:   result.Summary,
			Error:     result.Error,
			OpenPorts: len(result.Ports),
		})
	}
	return finding.FromPluginCollection(items), nil
}
