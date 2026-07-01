package scanctx

import (
	"context"
	"sync"

	"github.com/dionebastos/vibesec/internal/auth"
	"github.com/dionebastos/vibesec/internal/authorization"
	"github.com/dionebastos/vibesec/internal/ai"
	"github.com/dionebastos/vibesec/internal/bundle"
	"github.com/dionebastos/vibesec/internal/burp"
	"github.com/dionebastos/vibesec/internal/config"
	"github.com/dionebastos/vibesec/internal/endpoint"
	"github.com/dionebastos/vibesec/internal/finding"
	"github.com/dionebastos/vibesec/internal/fingerprint"
	"github.com/dionebastos/vibesec/internal/headers"
	"github.com/dionebastos/vibesec/internal/httpclient"
	"github.com/dionebastos/vibesec/internal/nuclei"
	"github.com/dionebastos/vibesec/internal/plugin"
)

type ReconAsset struct {
	Path    string
	Status  int
	Summary string
}

type Context struct {
	Target   string
	Config   *config.Config
	HTTP     *httpclient.Client
	Findings []finding.Finding
	ModulesRun int

	Fingerprint *fingerprint.Result
	Headers     *headers.Result
	Bundle      *bundle.Result
	Endpoints   *endpoint.Result
	Auth            *auth.Result
	Authorization   *authorization.Result
	Plugins         *plugin.Collection
	Nuclei          *nuclei.Result
	Burp            *burp.Result
	AI              *ai.Result
	ReconAssets     []ReconAsset

	ReportMarkdown string
	ReportJSON     string
	ReportHTML     string

	pageOnce sync.Once
	page     *httpclient.Response
	pageErr  error
}

func New(target string, cfg *config.Config) (*Context, error) {
	if cfg == nil {
		cfg = config.Default()
	}
	client, err := httpclient.NewFromConfig(cfg)
	if err != nil {
		return nil, err
	}
	return &Context{
		Target: target,
		Config: cfg,
		HTTP:   client,
	}, nil
}

func (c *Context) AddFindings(items ...finding.Finding) {
	c.Findings = finding.Dedup(append(c.Findings, finding.Enrich(items)...))
}

func (c *Context) FetchPage(ctx context.Context) (*httpclient.Response, error) {
	c.pageOnce.Do(func() {
		c.page, c.pageErr = c.HTTP.Get(ctx, c.Target)
	})
	return c.page, c.pageErr
}
