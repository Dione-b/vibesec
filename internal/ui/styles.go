package ui

import "github.com/charmbracelet/lipgloss"

var warnStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Bold(true)

func Muted(text string) string {
	return mutedStyle.Render(text)
}

func Warn(text string) string {
	return warnStyle.Render("! " + text)
}
