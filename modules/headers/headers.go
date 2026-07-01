package headers

import (
	"context"

	hdr "github.com/dionebastos/vibesec/internal/headers"
	"github.com/dionebastos/vibesec/internal/finding"
	"github.com/dionebastos/vibesec/internal/scanctx"
)

func Run(ctx *scanctx.Context) ([]finding.Finding, error) {
	resp, err := ctx.FetchPage(context.Background())
	if err != nil {
		return nil, err
	}

	result, err := hdr.Analyze(ctx.Target, resp, ctx.Config.Modules.CORS)
	if err != nil {
		return nil, err
	}
	ctx.Headers = result
	return finding.FromHeaderChecks(hdr.ToHeaderChecks(result)), nil
}
