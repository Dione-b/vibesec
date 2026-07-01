package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
)

func Load(path string) (*Config, error) {
	v := viper.New()
	setViperDefaults(v)

	if path != "" {
		v.SetConfigFile(path)
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("read config %s: %w", path, err)
		}
	} else if envPath := os.Getenv("VIBESEC_CONFIG"); envPath != "" {
		v.SetConfigFile(envPath)
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("read config %s: %w", envPath, err)
		}
	} else {
		v.SetConfigName("vibesec")
		v.SetConfigType("yaml")
		v.AddConfigPath(".")
		home, err := os.UserHomeDir()
		if err == nil {
			v.AddConfigPath(filepath.Join(home, ".config", "vibesec"))
		}
		if err := v.ReadInConfig(); err != nil {
			if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
				return nil, fmt.Errorf("read config: %w", err)
			}
		}
	}

	cfg := Default()
	if err := v.Unmarshal(cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func setViperDefaults(v *viper.Viper) {
	def := Default()
	v.SetDefault("threads", def.Threads)
	v.SetDefault("timeout", def.Timeout)
	v.SetDefault("http.max_redirects", def.HTTP.MaxRedirects)
	v.SetDefault("http.retries", def.HTTP.Retries)
	v.SetDefault("http.retry_backoff_ms", def.HTTP.RetryBackoffMS)
	v.SetDefault("report.format", def.Report.Format)
	v.SetDefault("plugins.enabled", def.Plugins.Enabled)
	v.SetDefault("plugins.httpx", def.Plugins.Httpx)
	v.SetDefault("plugins.nmap", def.Plugins.Nmap)
	v.SetDefault("plugins.katana", def.Plugins.Katana)
	v.SetDefault("plugins.subfinder", def.Plugins.Subfinder)
	v.SetDefault("plugins.naabu", def.Plugins.Naabu)
	v.SetDefault("plugins.dnsx", def.Plugins.Dnsx)
	v.SetDefault("nuclei.enabled", def.Nuclei.Enabled)
	v.SetDefault("nuclei.severity", def.Nuclei.Severity)
	v.SetDefault("nuclei.rate_limit", def.Nuclei.RateLimit)
	v.SetDefault("burp.enabled", def.Burp.Enabled)
	v.SetDefault("modules.fingerprint", def.Modules.Fingerprint)
	v.SetDefault("modules.bundle", def.Modules.Bundle)
	v.SetDefault("modules.endpoints", def.Modules.Endpoints)
	v.SetDefault("modules.headers", def.Modules.Headers)
	v.SetDefault("modules.cors", def.Modules.CORS)
	v.SetDefault("modules.csp", def.Modules.CSP)
	v.SetDefault("modules.auth", def.Modules.Auth)
	v.SetDefault("modules.authorization", def.Modules.Authorization)
	v.SetDefault("modules.plugins", def.Modules.Plugins)
	v.SetDefault("modules.nuclei", def.Modules.Nuclei)
	v.SetDefault("modules.burp", def.Modules.Burp)
	v.SetDefault("modules.report", def.Modules.Report)
}

func ConfigPathUsed(path string) string {
	if path != "" {
		return path
	}
	if envPath := os.Getenv("VIBESEC_CONFIG"); envPath != "" {
		return envPath
	}
	for _, candidate := range searchPaths() {
		full := filepath.Join(candidate, "vibesec.yaml")
		if _, err := os.Stat(full); err == nil {
			return full
		}
	}
	return ""
}

func searchPaths() []string {
	paths := []string{"."}
	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths, filepath.Join(home, ".config", "vibesec"))
	}
	return paths
}

func HasFormat(formats []string, name string) bool {
	name = strings.ToLower(name)
	for _, f := range formats {
		if strings.ToLower(f) == name {
			return true
		}
	}
	return false
}
