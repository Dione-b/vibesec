package endpoint

// DetectSPAFallback returns true when multiple distinct paths return identical content,
// indicating a client-side router serving the same shell for every route.
func DetectSPAFallback(probes []Probe) bool {
	hashCounts := make(map[string]int)
	pathsPerHash := make(map[string]map[string]struct{})

	for _, probe := range probes {
		if probe.Method != "GET" || probe.Status < 200 || probe.Status >= 400 {
			continue
		}
		if probe.ContentHash == "" {
			continue
		}
		hashCounts[probe.ContentHash]++
		if pathsPerHash[probe.ContentHash] == nil {
			pathsPerHash[probe.ContentHash] = make(map[string]struct{})
		}
		pathsPerHash[probe.ContentHash][probe.Path] = struct{}{}
	}

	for hash, paths := range pathsPerHash {
		if len(paths) >= 3 && hashCounts[hash] >= 3 {
			return true
		}
	}
	return false
}
