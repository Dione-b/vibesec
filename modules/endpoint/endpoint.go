package endpoint

import (
	"context"

	disc "github.com/dionebastos/vibesec/internal/endpoint"
	"github.com/dionebastos/vibesec/internal/finding"
	"github.com/dionebastos/vibesec/internal/scanctx"
)

func Run(ctx *scanctx.Context) ([]finding.Finding, error) {
	result, err := disc.Discover(context.Background(), ctx.Target, ctx.Bundle, ctx.HTTP)
	if err != nil {
		return nil, err
	}
	ctx.Endpoints = result

	probes := make([]finding.EndpointProbe, len(result.Matrix))
	for i, probe := range result.Matrix {
		probes[i] = finding.EndpointProbe{
			Path:   probe.Path,
			Method: probe.Method,
			Status: probe.Status,
		}
	}
	return finding.FromEndpoints(probes, result.SPADetected), nil
}
