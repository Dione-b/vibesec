package ai

import (
	aiengine "github.com/dionebastos/vibesec/internal/ai"
	"github.com/dionebastos/vibesec/internal/finding"
	"github.com/dionebastos/vibesec/internal/scanctx"
)

func Run(ctx *scanctx.Context) ([]finding.Finding, error) {
	ctx.AI = aiengine.Analyze(inputFromContext(ctx))
	return nil, nil
}

func inputFromContext(ctx *scanctx.Context) aiengine.Input {
	if ctx == nil {
		return aiengine.Input{}
	}
	in := aiengine.Input{
		Target:    ctx.Target,
		Findings:  append([]finding.Finding(nil), ctx.Findings...),
		Headers:   ctx.Headers,
		Bundle:    ctx.Bundle,
		Endpoints: ctx.Endpoints,
		Auth:      ctx.Auth,
		Plugins:   ctx.Plugins,
		Nuclei:    ctx.Nuclei,
	}
	if ctx.Fingerprint != nil {
		in.Stack = append([]string(nil), ctx.Fingerprint.Stack...)
		in.Infra = append([]string(nil), ctx.Fingerprint.Infra...)
	}
	return in
}
