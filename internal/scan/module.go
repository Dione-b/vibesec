package scan

import (
	"github.com/dionebastos/vibesec/internal/finding"
	"github.com/dionebastos/vibesec/internal/scanctx"
)

type Module struct {
	Name string
	Run  func(ctx *scanctx.Context) ([]finding.Finding, error)
}
