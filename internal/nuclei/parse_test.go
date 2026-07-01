package nuclei

import "testing"

func TestParseJSONL(t *testing.T) {
	raw := []byte(`{"template-id":"test-template","info":{"name":"Test Finding","severity":"high"},"matched-at":"https://example.com"}`)
	findings := ParseJSONL(raw)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].TemplateID != "test-template" {
		t.Fatalf("template id: %s", findings[0].TemplateID)
	}
}
