package burp

import (
	"strings"
	"testing"
)

func TestParseReader(t *testing.T) {
	raw := `<?xml version="1.0"?>
<issues>
  <issue>
    <name>Test issue</name>
    <severity>High</severity>
    <host>https://example.com</host>
    <location>https://example.com/admin</location>
    <issueDetail>detail</issueDetail>
  </issue>
</issues>`
	result, err := ParseReader(strings.NewReader(raw), "sample.xml")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Issues) != 1 {
		t.Fatalf("expected 1 issue, got %d", len(result.Issues))
	}
	if result.Issues[0].Name != "Test issue" {
		t.Fatalf("unexpected name: %s", result.Issues[0].Name)
	}
}
