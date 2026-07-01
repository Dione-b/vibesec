package ui

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"
)

var (
	passStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	failStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	warningStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Bold(true)
	detailStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
)

func CheckLine(name, status, detail string) string {
	var statusStyled string
	switch status {
	case "PASS":
		statusStyled = passStyle.Render("PASS")
	case "FAIL":
		statusStyled = failStyle.Render("FAIL")
	case "WARNING":
		statusStyled = warningStyle.Render("WARNING")
	default:
		statusStyled = status
	}

	line := fmt.Sprintf("  %-22s %s", name, statusStyled)
	if detail != "" {
		line += "  " + detailStyle.Render(detail)
	}
	return line
}
