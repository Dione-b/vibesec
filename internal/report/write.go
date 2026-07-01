package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/dionebastos/vibesec/internal/config"
)

var outputDir = "reports"

func Write(cfg *config.Config, doc *Document) (*Output, error) {
	return writeToDir(cfg, doc, outputDir)
}

func writeToDir(cfg *config.Config, doc *Document, dir string) (*Output, error) {
	if doc == nil {
		return nil, fmt.Errorf("report document is nil")
	}
	if cfg == nil {
		cfg = config.Default()
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create report dir: %w", err)
	}

	stamp := doc.Summary.GeneratedAt.Format("20060102-150405")
	baseName := fmt.Sprintf("%s-%s", slugTarget(doc.Summary.Target), stamp)
	output := &Output{}

	if config.HasFormat(cfg.Report.Format, "markdown") {
		path := filepath.Join(dir, baseName+".md")
		content := RenderMarkdown(doc)
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			return nil, fmt.Errorf("write markdown: %w", err)
		}
		output.Markdown = path
	}

	if config.HasFormat(cfg.Report.Format, "json") {
		path := filepath.Join(dir, baseName+".json")
		payload, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("marshal json: %w", err)
		}
		if err := os.WriteFile(path, payload, 0o644); err != nil {
			return nil, fmt.Errorf("write json: %w", err)
		}
		output.JSON = path
	}

	if config.HasFormat(cfg.Report.Format, "html") {
		path := filepath.Join(dir, baseName+".html")
		content := RenderHTML(doc)
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			return nil, fmt.Errorf("write html: %w", err)
		}
		output.HTML = path
	}

	if output.Markdown == "" && output.JSON == "" && output.HTML == "" {
		return nil, fmt.Errorf("no report formats enabled")
	}

	pointer := LatestPointer{
		Target:    doc.Summary.Target,
		Generated: doc.Summary.GeneratedAt,
		Markdown:  output.Markdown,
		JSON:      output.JSON,
		HTML:      output.HTML,
	}
	data, err := json.MarshalIndent(pointer, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "latest.json"), data, 0o644); err != nil {
		return nil, fmt.Errorf("write latest pointer: %w", err)
	}

	return output, nil
}

func LoadLatest(dir string) (*LatestPointer, error) {
	if dir == "" {
		dir = outputDir
	}
	data, err := os.ReadFile(filepath.Join(dir, "latest.json"))
	if err != nil {
		return nil, err
	}
	var pointer LatestPointer
	if err := json.Unmarshal(data, &pointer); err != nil {
		return nil, err
	}
	return &pointer, nil
}

func slugTarget(target string) string {
	target = strings.TrimSpace(target)
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimSuffix(target, "/")
	target = strings.ReplaceAll(target, "/", "-")
	target = strings.ReplaceAll(target, ":", "-")
	if target == "" {
		return "target"
	}
	return target
}

func FormatOutput(output *Output) []string {
	if output == nil {
		return nil
	}
	var lines []string
	if output.Markdown != "" {
		lines = append(lines, "  "+output.Markdown)
	}
	if output.JSON != "" {
		lines = append(lines, "  "+output.JSON)
	}
	if output.HTML != "" {
		lines = append(lines, "  "+output.HTML)
	}
	if len(lines) == 0 {
		return nil
	}
	return append([]string{""}, lines...)
}
