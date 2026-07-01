package authorization

import (
	authz "github.com/dionebastos/vibesec/internal/authorization"
	"github.com/dionebastos/vibesec/internal/finding"
	"github.com/dionebastos/vibesec/internal/scanctx"
)

func Run(ctx *scanctx.Context) ([]finding.Finding, error) {
	input := authz.Input{}
	if ctx.Bundle != nil {
		input.AdminPages = append([]string(nil), ctx.Bundle.AdminPages...)
	}
	if ctx.Endpoints != nil {
		for _, probe := range ctx.Endpoints.Matrix {
			input.EndpointProbes = append(input.EndpointProbes, authz.EndpointProbe{
				Path:   probe.Path,
				Method: probe.Method,
				Status: probe.Status,
			})
		}
	}

	result := authz.Analyze(input)
	ctx.Authorization = result

	signals := make([]finding.AuthSignal, len(result.Signals))
	for i, s := range result.Signals {
		signals[i] = finding.AuthSignal{Category: s.Category, Status: s.Status, Detail: s.Detail}
	}
	return finding.FromAuthorization(&finding.AuthorizationSnapshot{Signals: signals}), nil
}
