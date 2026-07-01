package config

import "time"

func (c *Config) Now() time.Time {
	return time.Now().UTC()
}

type Config struct {
	Threads    int              `mapstructure:"threads"`
	Timeout    int              `mapstructure:"timeout"`
	HTTP       HTTPConfig       `mapstructure:"http"`
	Report     ReportConfig     `mapstructure:"report"`
	Plugins    PluginsConfig    `mapstructure:"plugins"`
	Nuclei     NucleiConfig     `mapstructure:"nuclei"`
	Burp       BurpConfig       `mapstructure:"burp"`
	Modules    ModulesConfig    `mapstructure:"modules"`
	Enterprise EnterpriseConfig `mapstructure:"enterprise"`
}

type BurpConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	File    string `mapstructure:"file"`
}

type NucleiConfig struct {
	Enabled   bool     `mapstructure:"enabled"`
	Severity  []string `mapstructure:"severity"`
	RateLimit int      `mapstructure:"rate_limit"`
}

type PluginsConfig struct {
	Enabled   bool `mapstructure:"enabled"`
	Httpx     bool `mapstructure:"httpx"`
	Nmap      bool `mapstructure:"nmap"`
	Katana    bool `mapstructure:"katana"`
	Subfinder bool `mapstructure:"subfinder"`
	Naabu     bool `mapstructure:"naabu"`
	Dnsx      bool `mapstructure:"dnsx"`
}

type HTTPConfig struct {
	UserAgent       string `mapstructure:"user_agent"`
	Proxy           string `mapstructure:"proxy"`
	MaxRedirects    int    `mapstructure:"max_redirects"`
	Retries         int    `mapstructure:"retries"`
	RetryBackoffMS  int    `mapstructure:"retry_backoff_ms"`
}

type ReportConfig struct {
	Format []string `mapstructure:"format"`
}

type EnterpriseConfig struct {
	Enabled      bool   `mapstructure:"enabled"`
	Database     string `mapstructure:"database"`
	APIListen    string `mapstructure:"api_listen"`
	APIKey       string `mapstructure:"api_key"`
	PersistScans bool   `mapstructure:"persist_scans"`
}

type ModulesConfig struct {
	Fingerprint bool `mapstructure:"fingerprint"`
	Bundle      bool `mapstructure:"bundle"`
	Endpoints   bool `mapstructure:"endpoints"`
	Headers     bool `mapstructure:"headers"`
	CORS        bool `mapstructure:"cors"`
	CSP         bool `mapstructure:"csp"`
	Auth            bool `mapstructure:"auth"`
	Authorization   bool `mapstructure:"authorization"`
	Plugins         bool `mapstructure:"plugins"`
	Nuclei          bool `mapstructure:"nuclei"`
	Burp            bool `mapstructure:"burp"`
	Correlation     bool `mapstructure:"correlation"`
	AI              bool `mapstructure:"ai"`
	Report          bool `mapstructure:"report"`
}

func Default() *Config {
	return &Config{
		Threads: 20,
		Timeout: 10,
		HTTP: HTTPConfig{
			UserAgent:      "",
			MaxRedirects:   10,
			Retries:        3,
			RetryBackoffMS: 500,
		},
		Report: ReportConfig{
			Format: []string{"markdown", "json", "html"},
		},
		Enterprise: EnterpriseConfig{
			Database:     "vibesec.db",
			APIListen:    ":8080",
			PersistScans: true,
		},
		Plugins: PluginsConfig{
			Enabled:   true,
			Httpx:     true,
			Nmap:      true,
			Katana:    true,
			Subfinder: true,
			Naabu:     true,
			Dnsx:      true,
		},
		Nuclei: NucleiConfig{
			Enabled:   true,
			Severity:  []string{"critical", "high", "medium", "low"},
			RateLimit: 50,
		},
		Burp: BurpConfig{
			Enabled: true,
		},
		Modules: ModulesConfig{
			Fingerprint: true,
			Bundle:      true,
			Endpoints:   true,
			Headers:     true,
			CORS:        true,
			CSP:         true,
			Auth:          true,
			Authorization: true,
			Plugins:       true,
			Nuclei:        true,
			Burp:          true,
			Correlation:   true,
			AI:            true,
			Report:        true,
		},
	}
}

func (c *Config) Validate() error {
	if c.Threads <= 0 {
		c.Threads = Default().Threads
	}
	if c.Timeout <= 0 {
		c.Timeout = Default().Timeout
	}
	if len(c.Report.Format) == 0 {
		c.Report.Format = Default().Report.Format
	}
	if c.HTTP.MaxRedirects <= 0 {
		c.HTTP.MaxRedirects = Default().HTTP.MaxRedirects
	}
	if c.HTTP.Retries < 0 {
		c.HTTP.Retries = Default().HTTP.Retries
	}
	if c.HTTP.RetryBackoffMS <= 0 {
		c.HTTP.RetryBackoffMS = Default().HTTP.RetryBackoffMS
	}
	return nil
}
