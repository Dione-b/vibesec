package report

import (
	reportengine "github.com/dionebastos/vibesec/internal/report"
	"github.com/dionebastos/vibesec/internal/finding"
	"github.com/dionebastos/vibesec/internal/scanctx"
)

func Run(ctx *scanctx.Context) ([]finding.Finding, error) {
	doc := reportengine.Build(ctx, ctx.ModulesRun)
	output, err := reportengine.Write(ctx.Config, doc)
	if err != nil {
		return nil, err
	}
	ctx.ReportMarkdown = output.Markdown
	ctx.ReportJSON = output.JSON
	ctx.ReportHTML = output.HTML
	return nil, nil
}
