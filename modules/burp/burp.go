package burp

import (
	burpengine "github.com/dionebastos/vibesec/internal/burp"
	"github.com/dionebastos/vibesec/internal/finding"
	"github.com/dionebastos/vibesec/internal/scanctx"
)

func Run(ctx *scanctx.Context) ([]finding.Finding, error) {
	path := ""
	if ctx.Config != nil {
		path = ctx.Config.Burp.File
	}
	if path == "" {
		ctx.Burp = &burpengine.Result{Status: burpengine.StatusSkipped, Summary: "no burp file configured"}
		return nil, nil
	}

	result, err := burpengine.ParseFile(path)
	if err != nil {
		return nil, err
	}
	ctx.Burp = result

	var items []finding.BurpIssue
	for _, issue := range result.Issues {
		items = append(items, finding.BurpIssue{
			Name:        issue.Name,
			Severity:    issue.Severity,
			Location:    issue.Location,
			Detail:      issue.Detail,
			Remediation: issue.Remediation,
		})
	}
	return finding.FromBurp(items), nil
}
