package plugin

import "testing"

func TestParseNmapJSON(t *testing.T) {
	raw := []byte(`{
		"nmaprun": {
			"hosts": [{
				"ports": [{
					"portid": "443",
					"state": {"state": "open"},
					"service": {"name": "https"}
				}]
			}]
		}
	}`)
	ports := parseNmapJSON(raw)
	if len(ports) != 1 || ports[0].Number != 443 {
		t.Fatalf("unexpected ports: %+v", ports)
	}
}

func TestUniqueStrings(t *testing.T) {
	out := uniqueStrings([]string{"a", "a", "b", ""})
	if len(out) != 2 {
		t.Fatalf("expected 2, got %d", len(out))
	}
}
