package scan

import (
	"testing"

	"github.com/dionebastos/vibesec/internal/config"
)

func TestModulesFromConfig(t *testing.T) {
	cfg := config.Default()
	cfg.Modules.Fingerprint = false
	cfg.Modules.CSP = false
	cfg.Modules.Auth = false
	cfg.Modules.Authorization = false
	cfg.Modules.Plugins = false
	cfg.Modules.Nuclei = false
	cfg.Modules.Burp = false
	cfg.Modules.Correlation = false
	cfg.Modules.AI = false
	cfg.Modules.Report = false

	modules := ModulesFromConfig(cfg)
	if len(modules) != 3 {
		t.Fatalf("expected 3 modules, got %d", len(modules))
	}

	names := make([]string, len(modules))
	for i, m := range modules {
		names[i] = m.Name
	}
	want := []string{"Headers", "Bundle", "Endpoint Discovery"}
	for i, name := range want {
		if names[i] != name {
			t.Fatalf("module[%d]: got %q want %q (all: %v)", i, names[i], name, names)
		}
	}
}
