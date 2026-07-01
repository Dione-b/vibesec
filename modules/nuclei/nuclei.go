package nuclei

import (
	"context"

	nuc "github.com/dionebastos/vibesec/internal/nuclei"
	"github.com/dionebastos/vibesec/internal/finding"
	"github.com/dionebastos/vibesec/internal/scanctx"
)

func Run(ctx *scanctx.Context) ([]finding.Finding, error) {
	runner := nuc.NewRunner(ctx.Config)
	result := runner.Run(context.Background(), ctx.Target)
	ctx.Nuclei = result

	var items []finding.NucleiItem
	for _, item := range result.Findings {
		items = append(items, finding.NucleiItem{
			TemplateID: item.TemplateID,
			Name:       item.Name,
			Severity:   item.Severity,
			Matched:    item.Matched,
		})
	}
	return finding.FromNuclei(items), nil
}
