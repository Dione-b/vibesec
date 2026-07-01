package cmd

import (
	"sync"

	"github.com/dionebastos/vibesec/internal/config"
)

var (
	configPath string
	burpFile   string
	appConfig  *config.Config
	configOnce sync.Once
	configErr  error
)

func loadConfig() (*config.Config, error) {
	configOnce.Do(func() {
		appConfig, configErr = config.Load(configPath)
	})
	if configErr != nil {
		return nil, configErr
	}
	cfg := *appConfig
	if burpFile != "" {
		cfg.Burp.File = burpFile
		cfg.Burp.Enabled = true
		cfg.Modules.Burp = true
	}
	return &cfg, nil
}
