package scan

import (
	"testing"

	"github.com/dionebastos/vibesec/internal/config"
)

func TestModulesFromConfigIncludesAuth(t *testing.T) {
	cfg := config.Default()
	cfg.Modules.Auth = true
	modules := ModulesFromConfig(cfg)
	found := false
	for _, m := range modules {
		if m.Name == "Auth Scanner" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("auth scanner module missing")
	}
}
