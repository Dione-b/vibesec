package report

import (
	"testing"

	"github.com/dionebastos/vibesec/internal/config"
	"github.com/dionebastos/vibesec/internal/fingerprint"
	"github.com/dionebastos/vibesec/internal/scanctx"
)

func TestBuildFromContext(t *testing.T) {
	ctx := &scanctx.Context{
		Target: "https://example.com",
		Config: config.Default(),
		Fingerprint: &fingerprint.Result{
			Stack: []string{"Node"},
			Infra: []string{"AWS"},
		},
	}
	doc := Build(ctx, 3)
	if len(doc.Stack) != 1 || doc.Stack[0] != "Node" {
		t.Fatalf("stack: %#v", doc.Stack)
	}
}
