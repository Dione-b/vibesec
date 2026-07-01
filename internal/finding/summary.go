package finding

import "fmt"

type Summary struct {
	Total    int
	Critical int
	High     int
	Medium   int
	Low      int
	Info     int
}

func Summarize(items []Finding) Summary {
	var s Summary
	s.Total = len(items)
	for _, item := range items {
		switch item.Severity {
		case SeverityCritical:
			s.Critical++
		case SeverityHigh:
			s.High++
		case SeverityMedium:
			s.Medium++
		case SeverityLow:
			s.Low++
		default:
			s.Info++
		}
	}
	return s
}

func (s Summary) String() string {
	if s.Total == 0 {
		return "0 findings"
	}
	return fmt.Sprintf("%d findings (%d critical, %d high, %d medium, %d low, %d info)",
		s.Total, s.Critical, s.High, s.Medium, s.Low, s.Info)
}
