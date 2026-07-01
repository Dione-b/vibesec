package bundle

import (
	"context"

	bnd "github.com/dionebastos/vibesec/internal/bundle"
	"github.com/dionebastos/vibesec/internal/finding"
	"github.com/dionebastos/vibesec/internal/scanctx"
)

func Run(ctx *scanctx.Context) ([]finding.Finding, error) {
	page, err := ctx.FetchPage(context.Background())
	if err != nil {
		return nil, err
	}

	result, err := bnd.Analyze(context.Background(), ctx.Target, page, ctx.HTTP)
	if err != nil {
		return nil, err
	}
	ctx.Bundle = result

	return finding.FromBundle(&finding.BundleSnapshot{
		Secrets:    result.Secrets,
		AdminPages: result.AdminPages,
		Libraries:  result.Libraries,
	}), nil
}
