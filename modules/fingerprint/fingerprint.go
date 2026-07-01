package fingerprint

import (
	"context"

	fp "github.com/dionebastos/vibesec/internal/fingerprint"
	"github.com/dionebastos/vibesec/internal/finding"
	"github.com/dionebastos/vibesec/internal/scanctx"
)

func Run(ctx *scanctx.Context) ([]finding.Finding, error) {
	resp, err := ctx.FetchPage(context.Background())
	if err != nil {
		return nil, err
	}

	result, err := fp.Analyze(ctx.Target, resp)
	if err != nil {
		return nil, err
	}
	ctx.Fingerprint = result

	snapshot := &finding.FingerprintSnapshot{
		Stack:      result.Stack,
		Infra:      result.Infra,
		TLSVersion: result.TLS.Version,
	}
	return finding.FromFingerprint(snapshot), nil
}
