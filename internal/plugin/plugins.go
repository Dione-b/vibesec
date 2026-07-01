package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

func (r *Runner) runHttpx(ctx context.Context, target, host string) Result {
	const name = "httpx"
	if !r.cfg.Httpx {
		return Result{Name: name, Status: StatusSkipped, Summary: "disabled in config"}
	}
	if !r.executor.Available(name) {
		return skipped(name)
	}

	raw, err := r.executor.Run(ctx, name,
		"-u", target,
		"-json",
		"-silent",
		"-status-code",
		"-title",
		"-tech-detect",
		"-no-color",
	)
	result := Result{Name: name}
	if err != nil {
		result.Status = StatusError
		result.Error = err.Error()
		return withRaw(result, raw)
	}

	var urls []string
	var tech []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var row struct {
			URL          string   `json:"url"`
			Technologies []string `json:"tech"`
		}
		if json.Unmarshal([]byte(line), &row) == nil {
			if row.URL != "" {
				urls = append(urls, row.URL)
			}
			tech = append(tech, row.Technologies...)
		}
	}
	result.Status = StatusOK
	result.URLs = uniqueStrings(urls)
	result.Technologies = uniqueStrings(tech)
	result.Summary = fmt.Sprintf("%d urls, %d technologies", len(result.URLs), len(result.Technologies))
	return withRaw(result, raw)
}

func (r *Runner) runNmap(ctx context.Context, target, host string) Result {
	const name = "nmap"
	if !r.cfg.Nmap {
		return Result{Name: name, Status: StatusSkipped, Summary: "disabled in config"}
	}
	if !r.executor.Available(name) {
		return skipped(name)
	}

	raw, err := r.executor.Run(ctx, name,
		"-Pn", "-F", "--open",
		"-oJ", "-",
		host,
	)
	result := Result{Name: name}
	if err != nil {
		result.Status = StatusError
		result.Error = err.Error()
		return withRaw(result, raw)
	}

	ports := parseNmapJSON(raw)
	result.Ports = ports
	result.Status = StatusOK
	result.Summary = fmt.Sprintf("%d open ports", len(ports))
	return withRaw(result, raw)
}

func parseNmapJSON(raw []byte) []Port {
	var payload struct {
		NmapRun struct {
			Hosts []struct {
				Ports []struct {
					PortID string `json:"portid"`
					State  struct {
						State string `json:"state"`
					} `json:"state"`
					Service struct {
						Name string `json:"name"`
					} `json:"service"`
				} `json:"ports"`
			} `json:"hosts"`
		} `json:"nmaprun"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil
	}
	var ports []Port
	for _, host := range payload.NmapRun.Hosts {
		for _, p := range host.Ports {
			num := 0
			_, _ = fmt.Sscanf(p.PortID, "%d", &num)
			if num == 0 {
				continue
			}
			ports = append(ports, Port{
				Number:  num,
				Service: p.Service.Name,
				State:   p.State.State,
			})
		}
	}
	return ports
}

func (r *Runner) runKatana(ctx context.Context, target, host string) Result {
	const name = "katana"
	if !r.cfg.Katana {
		return Result{Name: name, Status: StatusSkipped, Summary: "disabled in config"}
	}
	if !r.executor.Available(name) {
		return skipped(name)
	}

	raw, err := r.executor.Run(ctx, name,
		"-u", target,
		"-json",
		"-silent",
		"-d", "1",
		"-no-color",
	)
	result := Result{Name: name}
	if err != nil {
		result.Status = StatusError
		result.Error = err.Error()
		return withRaw(result, raw)
	}

	var urls []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var row struct {
			Request struct {
				Endpoint string `json:"endpoint"`
			} `json:"request"`
		}
		if json.Unmarshal([]byte(line), &row) == nil && row.Request.Endpoint != "" {
			urls = append(urls, row.Request.Endpoint)
		}
	}
	result.URLs = uniqueStrings(urls)
	result.Status = StatusOK
	result.Summary = fmt.Sprintf("%d urls crawled", len(result.URLs))
	return withRaw(result, raw)
}

func (r *Runner) runSubfinder(ctx context.Context, target, host string) Result {
	const name = "subfinder"
	if !r.cfg.Subfinder {
		return Result{Name: name, Status: StatusSkipped, Summary: "disabled in config"}
	}
	if !r.executor.Available(name) {
		return skipped(name)
	}

	raw, err := r.executor.Run(ctx, name,
		"-d", host,
		"-silent",
		"-oJ",
	)
	result := Result{Name: name}
	if err != nil {
		// subfinder may not support -oJ in all versions; fallback plain
		raw, err = r.executor.Run(ctx, name, "-d", host, "-silent")
		if err != nil {
			result.Status = StatusError
			result.Error = err.Error()
			return withRaw(result, raw)
		}
		lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
		result.Subdomains = uniqueStrings(lines)
		result.Status = StatusOK
		result.Summary = fmt.Sprintf("%d subdomains", len(result.Subdomains))
		return withRaw(result, raw)
	}

	var subs []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var row struct {
			Host string `json:"host"`
		}
		if json.Unmarshal([]byte(line), &row) == nil && row.Host != "" {
			subs = append(subs, row.Host)
		}
	}
	result.Subdomains = uniqueStrings(subs)
	result.Status = StatusOK
	result.Summary = fmt.Sprintf("%d subdomains", len(result.Subdomains))
	return withRaw(result, raw)
}

func (r *Runner) runNaabu(ctx context.Context, target, host string) Result {
	const name = "naabu"
	if !r.cfg.Naabu {
		return Result{Name: name, Status: StatusSkipped, Summary: "disabled in config"}
	}
	if !r.executor.Available(name) {
		return skipped(name)
	}

	raw, err := r.executor.Run(ctx, name,
		"-host", host,
		"-json",
		"-silent",
	)
	result := Result{Name: name}
	if err != nil {
		result.Status = StatusError
		result.Error = err.Error()
		return withRaw(result, raw)
	}

	var ports []Port
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var row struct {
			Port int `json:"port"`
		}
		if json.Unmarshal([]byte(line), &row) == nil && row.Port > 0 {
			ports = append(ports, Port{Number: row.Port, State: "open"})
		}
	}
	result.Ports = ports
	result.Status = StatusOK
	result.Summary = fmt.Sprintf("%d open ports", len(ports))
	return withRaw(result, raw)
}

func (r *Runner) runDnsx(ctx context.Context, target, host string) Result {
	const name = "dnsx"
	if !r.cfg.Dnsx {
		return Result{Name: name, Status: StatusSkipped, Summary: "disabled in config"}
	}
	if !r.executor.Available(name) {
		return skipped(name)
	}

	raw, err := r.executor.Run(ctx, name,
		"-d", host,
		"-json",
		"-silent",
	)
	result := Result{Name: name}
	if err != nil {
		result.Status = StatusError
		result.Error = err.Error()
		return withRaw(result, raw)
	}

	var hosts []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var row struct {
			Host string `json:"host"`
			A    []string `json:"a"`
		}
		if json.Unmarshal([]byte(line), &row) == nil {
			if row.Host != "" {
				hosts = append(hosts, row.Host)
			}
		}
	}
	result.Hosts = uniqueStrings(hosts)
	result.Status = StatusOK
	result.Summary = fmt.Sprintf("%d dns records", len(result.Hosts))
	return withRaw(result, raw)
}

func uniqueStrings(items []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}
