package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vibesec.yaml")
	content := `threads: 8
timeout: 5
report:
  format:
    - json
modules:
  fingerprint: false
  bundle: true
  endpoints: false
  headers: true
  cors: false
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Threads != 8 {
		t.Fatalf("threads: got %d want 8", cfg.Threads)
	}
	if cfg.Timeout != 5 {
		t.Fatalf("timeout: got %d want 5", cfg.Timeout)
	}
	if !HasFormat(cfg.Report.Format, "json") {
		t.Fatalf("expected json in report formats: %v", cfg.Report.Format)
	}
	if cfg.Modules.Fingerprint {
		t.Fatal("fingerprint should be disabled")
	}
	if !cfg.Modules.Bundle {
		t.Fatal("bundle should be enabled")
	}
}

func TestLoadDefaultsWhenMissing(t *testing.T) {
	dir := t.TempDir()
	oldWD, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(oldWD) })
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}

	def := Default()
	if cfg.Threads != def.Threads {
		t.Fatalf("threads: got %d want %d", cfg.Threads, def.Threads)
	}
	if !cfg.Modules.Fingerprint {
		t.Fatal("fingerprint should default to true")
	}
}

func TestValidateFixesInvalidValues(t *testing.T) {
	cfg := &Config{Threads: 0, Timeout: -1, Report: ReportConfig{}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Threads != 20 || cfg.Timeout != 10 {
		t.Fatalf("unexpected defaults: threads=%d timeout=%d", cfg.Threads, cfg.Timeout)
	}
}
