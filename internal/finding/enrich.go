package finding

type Enrichment struct {
	CWE   string
	OWASP string
	ASVS  string
	CAPEC string
	CVSS  float64
}

var enrichmentByCWE = map[string]Enrichment{
	"CWE-319": {CWE: "CWE-319", OWASP: "A02:2021", ASVS: "V9.1", CAPEC: "CAPEC-117", CVSS: 5.3},
	"CWE-614": {CWE: "CWE-614", OWASP: "A05:2021", ASVS: "V3.4", CAPEC: "CAPEC-102", CVSS: 5.9},
	"CWE-1004": {CWE: "CWE-1004", OWASP: "A05:2021", ASVS: "V3.4", CAPEC: "CAPEC-31", CVSS: 5.4},
	"CWE-1275": {CWE: "CWE-1275", OWASP: "A05:2021", ASVS: "V3.4", CAPEC: "CAPEC-31", CVSS: 4.3},
	"CWE-1021": {CWE: "CWE-1021", OWASP: "A05:2021", ASVS: "V14.4", CAPEC: "CAPEC-103", CVSS: 6.1},
	"CWE-352": {CWE: "CWE-352", OWASP: "A01:2021", ASVS: "V4.2", CAPEC: "CAPEC-62", CVSS: 6.5},
	"CWE-798": {CWE: "CWE-798", OWASP: "A02:2021", ASVS: "V6.4", CAPEC: "CAPEC-37", CVSS: 7.5},
	"CWE-639": {CWE: "CWE-639", OWASP: "A01:2021", ASVS: "V4.1", CAPEC: "CAPEC-1", CVSS: 6.5},
	"CWE-284": {CWE: "CWE-284", OWASP: "A01:2021", ASVS: "V4.1", CAPEC: "CAPEC-122", CVSS: 5.4},
	"CWE-326": {CWE: "CWE-326", OWASP: "A02:2021", ASVS: "V9.1", CAPEC: "CAPEC-94", CVSS: 5.9},
	"CWE-79":  {CWE: "CWE-79", OWASP: "A03:2021", ASVS: "V5.3", CAPEC: "CAPEC-86", CVSS: 6.1},
	"CWE-95":  {CWE: "CWE-95", OWASP: "A03:2021", ASVS: "V5.3", CAPEC: "CAPEC-242", CVSS: 5.4},
	"CWE-942": {CWE: "CWE-942", OWASP: "A01:2021", ASVS: "V4.1", CAPEC: "CAPEC-122", CVSS: 6.5},
	"CWE-200": {CWE: "CWE-200", OWASP: "A01:2021", ASVS: "V7.1", CAPEC: "CAPEC-116", CVSS: 3.7},
	"CWE-915": {CWE: "CWE-915", OWASP: "A01:2021", ASVS: "V4.1", CAPEC: "CAPEC-122", CVSS: 5.4},
	"CWE-602": {CWE: "CWE-602", OWASP: "A01:2021", ASVS: "V4.1", CAPEC: "CAPEC-122", CVSS: 5.4},
	"CWE-384": {CWE: "CWE-384", OWASP: "A07:2021", ASVS: "V3.2", CAPEC: "CAPEC-60", CVSS: 4.3},
	"CWE-287": {CWE: "CWE-287", OWASP: "A07:2021", ASVS: "V4.1", CAPEC: "CAPEC-115", CVSS: 6.1},
	"CWE-922": {CWE: "CWE-922", OWASP: "A02:2021", ASVS: "V3.4", CAPEC: "CAPEC-37", CVSS: 5.4},
}

var enrichmentByModule = map[string]Enrichment{
	ModuleHeaders + "/csp":        enrichmentByCWE["CWE-1021"],
	ModuleHeaders + "/hsts":       enrichmentByCWE["CWE-319"],
	ModuleHeaders + "/cookies-secure": enrichmentByCWE["CWE-614"],
	ModuleBurp + "/cookie-without-secure-flag-0": enrichmentByCWE["CWE-614"],
}

func Enrich(items []Finding) []Finding {
	out := make([]Finding, len(items))
	for i, item := range items {
		out[i] = enrichOne(item)
	}
	return out
}

func enrichOne(item Finding) Finding {
	if meta, ok := enrichmentByCWE[item.CWE]; ok {
		item = applyEnrichment(item, meta)
	}
	if meta, ok := enrichmentByModule[item.ID]; ok {
		item = applyEnrichment(item, meta)
	}
	if item.CVSS == 0 {
		item.CVSS = defaultCVSS(item.Severity)
	}
	return item
}

func applyEnrichment(item Finding, meta Enrichment) Finding {
	if item.CWE == "" {
		item.CWE = meta.CWE
	}
	if item.OWASP == "" {
		item.OWASP = meta.OWASP
	}
	if item.ASVS == "" {
		item.ASVS = meta.ASVS
	}
	if item.CAPEC == "" {
		item.CAPEC = meta.CAPEC
	}
	if item.CVSS == 0 && meta.CVSS > 0 {
		item.CVSS = meta.CVSS
	}
	return item
}

func defaultCVSS(severity string) float64 {
	switch severity {
	case SeverityCritical:
		return 9.0
	case SeverityHigh:
		return 7.0
	case SeverityMedium:
		return 5.0
	case SeverityLow:
		return 3.0
	default:
		return 0.0
	}
}
