package scan

import (
	"github.com/dionebastos/vibesec/internal/config"
	"github.com/dionebastos/vibesec/modules/auth"
	"github.com/dionebastos/vibesec/modules/authorization"
	"github.com/dionebastos/vibesec/modules/bundle"
	"github.com/dionebastos/vibesec/modules/csp"
	"github.com/dionebastos/vibesec/modules/endpoint"
	"github.com/dionebastos/vibesec/modules/fingerprint"
	"github.com/dionebastos/vibesec/modules/headers"
	modai "github.com/dionebastos/vibesec/modules/ai"
	modburp "github.com/dionebastos/vibesec/modules/burp"
	modcorrelation "github.com/dionebastos/vibesec/modules/correlation"
	modnuclei "github.com/dionebastos/vibesec/modules/nuclei"
	modplugins "github.com/dionebastos/vibesec/modules/plugins"
	modreport "github.com/dionebastos/vibesec/modules/report"
)

func ModulesFromConfig(cfg *config.Config) []Module {
	if cfg == nil {
		cfg = config.Default()
	}

	candidates := []struct {
		enabled bool
		module  Module
	}{
		{cfg.Modules.Fingerprint, Module{Name: "Fingerprint", Run: fingerprint.Run}},
		{cfg.Modules.Headers, Module{Name: "Headers", Run: headers.Run}},
		{cfg.Modules.CSP, Module{Name: "CSP", Run: csp.Run}},
		{cfg.Modules.Bundle, Module{Name: "Bundle", Run: bundle.Run}},
		{cfg.Modules.Endpoints, Module{Name: "Endpoint Discovery", Run: endpoint.Run}},
		{cfg.Modules.Auth, Module{Name: "Auth Scanner", Run: auth.Run}},
		{cfg.Modules.Authorization, Module{Name: "Authorization Scanner", Run: authorization.Run}},
		{cfg.Modules.Plugins, Module{Name: "Plugins", Run: modplugins.Run}},
		{cfg.Modules.Nuclei, Module{Name: "Nuclei", Run: modnuclei.Run}},
		{cfg.Modules.Burp, Module{Name: "Burp", Run: modburp.Run}},
		{cfg.Modules.Correlation, Module{Name: "Correlation", Run: modcorrelation.Run}},
		{cfg.Modules.AI, Module{Name: "AI Analyzer", Run: modai.Run}},
		{cfg.Modules.Report, Module{Name: "Report", Run: modreport.Run}},
	}

	var modules []Module
	for _, c := range candidates {
		if c.enabled {
			modules = append(modules, c.module)
		}
	}
	return modules
}

func DefaultModules() []Module {
	return ModulesFromConfig(config.Default())
}
