package httpclient

import (
	"time"

	"github.com/dionebastos/vibesec/internal/config"
)

const defaultUserAgent = "VibeSec/0.1 (+https://github.com/dionebastos/vibesec)"

type Options struct {
	Timeout      time.Duration
	UserAgent    string
	ProxyURL     string
	MaxRedirects int
	Retries      int
	RetryBackoff time.Duration
}

func OptionsFromConfig(cfg *config.Config) Options {
	if cfg == nil {
		cfg = config.Default()
	}
	opts := Options{
		Timeout:      time.Duration(cfg.Timeout) * time.Second,
		UserAgent:    cfg.HTTP.UserAgent,
		ProxyURL:     cfg.HTTP.Proxy,
		MaxRedirects: cfg.HTTP.MaxRedirects,
		Retries:      cfg.HTTP.Retries,
		RetryBackoff: time.Duration(cfg.HTTP.RetryBackoffMS) * time.Millisecond,
	}
	opts.applyDefaults()
	return opts
}

func (o *Options) applyDefaults() {
	if o.Timeout <= 0 {
		o.Timeout = 10 * time.Second
	}
	if o.UserAgent == "" {
		o.UserAgent = defaultUserAgent
	}
	if o.MaxRedirects <= 0 {
		o.MaxRedirects = 10
	}
	if o.Retries < 0 {
		o.Retries = 0
	}
	if o.RetryBackoff <= 0 {
		o.RetryBackoff = 500 * time.Millisecond
	}
}
