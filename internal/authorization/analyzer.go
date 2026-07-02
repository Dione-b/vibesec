package authorization

import (
	"net/http"
	"regexp"
	"strings"
)

type Input struct {
	AdminPages     []string
	EndpointProbes []EndpointProbe
	BundleContent  string
	SPADetected    bool
}

type EndpointProbe struct {
	Path   string
	Method string
	Status int
}

var (
	idorPathPattern = regexp.MustCompile(`(?i)/(?:users|accounts|orders|invoices|profile)/\{?[:\w]*id\}?`)
	idorNumeric     = regexp.MustCompile(`(?i)/(?:users|accounts)/\d+`)
	massAssign      = regexp.MustCompile(`(?i)(mass.?assign|req\.body|Object\.assign\([^)]*user)`)
	roleBypass      = regexp.MustCompile(`(?i)(isAdmin\s*&&\s*bypass|bypass.*auth|role\s*===\s*['"]admin['"].*bypass)`)
)

func Analyze(in Input) *Result {
	result := &Result{
		AdminPaths: append([]string(nil), in.AdminPages...),
	}

	body := in.BundleContent
	for _, probe := range in.EndpointProbes {
		if probe.Method != http.MethodGet || probe.Status >= 400 {
			continue
		}
		lower := strings.ToLower(probe.Path)
		if strings.Contains(lower, "/admin") {
			result.AdminPaths = appendUnique(result.AdminPaths, probe.Path)
		}
		if idorNumeric.MatchString(probe.Path) {
			result.IDORCandidates = appendUnique(result.IDORCandidates, probe.Path)
		}
	}

	result.Signals = append(result.Signals, analyzeAdmin(result.AdminPaths)...)
	result.Signals = append(result.Signals, analyzeIDOR(body, result.IDORCandidates)...)
	result.Signals = append(result.Signals, analyzeMassAssignment(body)...)
	result.Signals = append(result.Signals, analyzeRoleBypass(body)...)
	result.Signals = append(result.Signals, analyzeVertical(result.AdminPaths, in.EndpointProbes, in.SPADetected)...)

	return result
}

func analyzeAdmin(paths []string) []Signal {
	if len(paths) == 0 {
		return []Signal{{Category: "Admin pages", Status: StatusInfo, Detail: "no admin routes identified"}}
	}
	return []Signal{{
		Category: "Admin pages",
		Status:   StatusWarning,
		Detail:   strings.Join(paths, ", ") + " referenced or reachable",
	}}
}

func analyzeIDOR(body string, paths []string) []Signal {
	if idorPathPattern.MatchString(body) {
		return []Signal{{
			Category: "IDOR",
			Status:   StatusWarning,
			Detail:   "parameterized user-specific routes found in client code",
		}}
	}
	if len(paths) > 0 {
		return []Signal{{
			Category: "IDOR",
			Status:   StatusWarning,
			Detail:   "numeric object paths discovered: " + strings.Join(paths, ", "),
		}}
	}
	return []Signal{{Category: "IDOR", Status: StatusPass, Detail: "no obvious IDOR patterns"}}
}

func analyzeMassAssignment(body string) []Signal {
	if massAssign.MatchString(body) {
		return []Signal{{
			Category: "Mass Assignment",
			Status:   StatusWarning,
			Detail:   "client code may forward unfiltered request bodies",
		}}
	}
	return []Signal{{Category: "Mass Assignment", Status: StatusPass, Detail: "no obvious mass assignment patterns"}}
}

func analyzeRoleBypass(body string) []Signal {
	if roleBypass.MatchString(body) {
		return []Signal{{
			Category: "Role bypass",
			Status:   StatusFail,
			Detail:   "client-side admin/role bypass patterns detected",
		}}
	}
	return []Signal{{Category: "Role bypass", Status: StatusPass, Detail: "no client-side role bypass patterns"}}
}

func analyzeVertical(adminPaths []string, probes []EndpointProbe, spaDetected bool) []Signal {
	if spaDetected {
		return []Signal{{Category: "Vertical escalation", Status: StatusPass, Detail: "SPA fallback detected; admin 200 responses ignored"}}
	}
	for _, path := range adminPaths {
		for _, probe := range probes {
			if probe.Path == path && probe.Method == http.MethodGet && probe.Status == 200 {
				return []Signal{{
					Category: "Vertical escalation",
					Status:   StatusWarning,
					Detail:   path + " responds 200 to unauthenticated GET",
				}}
			}
		}
	}
	return []Signal{{Category: "Vertical escalation", Status: StatusPass, Detail: "no admin routes returned 200"}}
}

func appendUnique(items []string, value string) []string {
	for _, item := range items {
		if item == value {
			return items
		}
	}
	return append(items, value)
}
