package ui

import "github.com/charmbracelet/lipgloss"

var subStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("39")).Bold(true)

func Subsection(title string) string {
	return subStyle.Render(title)
}
