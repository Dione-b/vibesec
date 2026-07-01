package report

import (
	"time"

	"github.com/dionebastos/vibesec/internal/endpoint"
	"github.com/dionebastos/vibesec/internal/finding"
	"github.com/dionebastos/vibesec/internal/headers"
	"github.com/dionebastos/vibesec/internal/scanctx"
)

func Build(ctx *scanctx.Context, modulesRun int) *Document {
	if ctx == nil {
		return &Document{}
	}

	doc := &Document{
		Summary: Summary{
			Target:      ctx.Target,
			GeneratedAt: timeNow(),
			ModulesRun:  modulesRun,
		},
		Fingerprint: ctx.Fingerprint,
	}

	if ctx.Fingerprint != nil {
		doc.Stack = append([]string(nil), ctx.Fingerprint.Stack...)
		doc.Infrastructure = append([]string(nil), ctx.Fingerprint.Infra...)
	}
	if ctx.Headers != nil {
		doc.HeaderChecks = append([]headers.Check(nil), ctx.Headers.Checks...)
	}
	if ctx.Bundle != nil {
		copyBundle := *ctx.Bundle
		doc.Bundle = &copyBundle
	}
	if ctx.Endpoints != nil {
		doc.Endpoints = append([]endpoint.Probe(nil), ctx.Endpoints.Matrix...)
	}
	if ctx.Auth != nil {
		copyAuth := *ctx.Auth
		doc.Auth = &copyAuth
	}
	if ctx.Plugins != nil {
		doc.Plugins = ctx.Plugins
	}
	if ctx.Nuclei != nil {
		copyNuclei := *ctx.Nuclei
		doc.Nuclei = &copyNuclei
	}
	if ctx.Burp != nil {
		copyBurp := *ctx.Burp
		doc.Burp = &copyBurp
	}
	if ctx.AI != nil {
		copyAI := *ctx.AI
		doc.AI = &copyAI
	}
	if ctx.ReconAssets != nil {
		doc.ReconAssets = make([]ReconAsset, len(ctx.ReconAssets))
		for i, asset := range ctx.ReconAssets {
			doc.ReconAssets[i] = ReconAsset{
				Path:    asset.Path,
				Status:  asset.Status,
				Summary: asset.Summary,
			}
		}
	}

	doc.Findings = append([]finding.Finding(nil), ctx.Findings...)
	doc.Summary.FindingCount = len(doc.Findings)
	doc.Risk = assessRisk(doc.Findings, doc.HeaderChecks)
	doc.Recommendations = buildRecommendations(doc)
	return doc
}

var timeNow = func() time.Time {
	return time.Now().UTC()
}
