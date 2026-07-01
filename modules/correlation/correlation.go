package correlation

import (
	correngine "github.com/dionebastos/vibesec/internal/correlation"
	"github.com/dionebastos/vibesec/internal/finding"
	"github.com/dionebastos/vibesec/internal/scanctx"
)

func Run(ctx *scanctx.Context) ([]finding.Finding, error) {
	return correngine.Analyze(correngine.FromContext(ctx)), nil
}
