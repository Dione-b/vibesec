package bundle

import (
	"math"
	"regexp"
	"strings"
	"unicode"
)

var placeholderPattern = regexp.MustCompile(`(?i)(example|test|dummy|changeme|placeholder|your[-_]?api[-_]?key|sample|fake|todo|xxx+|null|undefined|process\.env|\$\{|^\{.*\}$)`)

// IsLikelySecret returns true when a captured value looks like a real secret rather than a placeholder.
func IsLikelySecret(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	if len(value) < 12 {
		return false
	}
	if placeholderPattern.MatchString(value) {
		return false
	}
	if isRepetitive(value) {
		return false
	}
	if isUpperSnakeIdentifier(value) && shannonEntropy(value) < 3.8 {
		return false
	}
	return shannonEntropy(value) >= 3.5
}

func isRepetitive(value string) bool {
	if len(value) < 3 {
		return true
	}
	first := value[0]
	allSame := true
	for i := 1; i < len(value); i++ {
		if value[i] != first {
			allSame = false
			break
		}
	}
	if allSame {
		return true
	}

	if strings.Contains("0123456789", value) || strings.Contains("9876543210", value) {
		return true
	}
	return false
}

func isUpperSnakeIdentifier(value string) bool {
	hasUpper := false
	hasUnderscore := false
	for _, r := range value {
		if unicode.IsUpper(r) {
			hasUpper = true
		}
		if r == '_' {
			hasUnderscore = true
		}
		if unicode.IsLower(r) {
			return false
		}
	}
	return hasUpper && hasUnderscore
}

func shannonEntropy(value string) float64 {
	if value == "" {
		return 0
	}
	freq := make(map[rune]int, len(value))
	for _, r := range value {
		freq[r]++
	}
	var entropy float64
	length := float64(len(value))
	for _, count := range freq {
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}
