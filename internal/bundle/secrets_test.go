package bundle

import "testing"

func TestIsLikelySecretRejectsPlaceholders(t *testing.T) {
	placeholders := []string{
		"your-api-key-here",
		"changeme",
		"example_secret_value",
		"test_token_123",
		"aaaaaaaaaaaaaaaa",
		"123456789012",
		"SHORT",
	}
	for _, value := range placeholders {
		if IsLikelySecret(value) {
			t.Fatalf("expected placeholder %q to be rejected", value)
		}
	}
}

func TestIsLikelySecretAcceptsHighEntropy(t *testing.T) {
	values := []string{
		"k8Jx2mP9vQw3nR7sT1uY4z",
		"sk_live_51Hq9k2mP9vQw3nR7sT1u",
	}
	for _, value := range values {
		if !IsLikelySecret(value) {
			t.Fatalf("expected %q to be accepted as likely secret", value)
		}
	}
}

func TestScanContentSkipsPlaceholderSecrets(t *testing.T) {
	result := &Result{}
	seen := make(map[string]struct{})
	content := `
		const config = {
			api_key: "your-api-key-here",
			password: "changeme",
		};
	`
	scanContent(content, result, seen)
	if len(result.Secrets) != 0 {
		t.Fatalf("expected no secrets, got %v", result.Secrets)
	}
}
