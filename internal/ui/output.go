package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

var (
	labelStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	okStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true)
	titleStyle = lipgloss.NewStyle().Bold(true)
	mutedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
)

func TargetBlock(target string) string {
	return fmt.Sprintf("%s\n%s\n", titleStyle.Render("Target:"), target)
}

func ModuleOK(name string) string {
	return fmt.Sprintf("%s %s", okStyle.Render("✓"), name)
}

func Done() string {
	return mutedStyle.Render("Done.")
}

func Section(title string) string {
	return titleStyle.Render(title)
}

func Bullet(lines ...string) string {
	return strings.Join(lines, "\n")
}
