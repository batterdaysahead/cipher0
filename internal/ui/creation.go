// Package ui provides the TUI interface for the password manager.
package ui

import (
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/batterdaysahead/cipher0/internal/utils"
	"github.com/batterdaysahead/cipher0/internal/vault"
)

type CreationModel struct {
	passwordInput    textinput.Model
	confirmInput     textinput.Model
	focusIndex       int
	error            string
	passwordStrength utils.PasswordStrength
}

func NewCreationModel() *CreationModel {
	pi := textinput.New()
	pi.Placeholder = ""
	pi.Focus()
	pi.EchoMode = textinput.EchoPassword
	pi.EchoCharacter = '•'
	pi.Width = 40
	pi.Prompt = ""
	pi.PlaceholderStyle = InputPlaceholderStyle
	pi.TextStyle = lipgloss.NewStyle().Foreground(ColorWhite)

	ci := textinput.New()
	ci.Placeholder = ""
	ci.EchoMode = textinput.EchoPassword
	ci.EchoCharacter = '•'
	ci.Width = 40
	ci.Prompt = ""
	ci.PlaceholderStyle = InputPlaceholderStyle
	ci.TextStyle = lipgloss.NewStyle().Foreground(ColorWhite)

	return &CreationModel{passwordInput: pi, confirmInput: ci}
}

func (m *CreationModel) Init() tea.Cmd { return textinput.Blink }

func (m *CreationModel) Update(msg tea.Msg, vaultPath string) (*CreationModel, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyTab, tea.KeyDown:
			m.focusIndex = (m.focusIndex + 1) % 2
			m.updateFocus()
			return m, nil
		case tea.KeyShiftTab, tea.KeyUp:
			m.focusIndex = (m.focusIndex + 1) % 2
			m.updateFocus()
			return m, nil
		case tea.KeyEnter:
			if m.focusIndex == 0 {
				m.focusIndex = 1
				m.updateFocus()
				return m, nil
			}
			return m.createVault(vaultPath)
		case tea.KeyEsc, tea.KeyCtrlC:
			return m, tea.Quit
		}
	}

	if m.focusIndex == 0 {
		m.passwordInput, cmd = m.passwordInput.Update(msg)
		m.passwordStrength = utils.CalculateStrength(m.passwordInput.Value())
	} else {
		m.confirmInput, cmd = m.confirmInput.Update(msg)
	}
	return m, cmd
}

func (m *CreationModel) updateFocus() {
	if m.focusIndex == 0 {
		m.passwordInput.Focus()
		m.confirmInput.Blur()
	} else {
		m.passwordInput.Blur()
		m.confirmInput.Focus()
	}
}

func (m *CreationModel) createVault(vaultPath string) (*CreationModel, tea.Cmd) {
	password := m.passwordInput.Value()
	confirm := m.confirmInput.Value()

	if password == "" {
		m.error = "Password required"
		return m, nil
	}
	if len(password) < 8 {
		m.error = "Minimum 8 characters"
		return m, nil
	}
	if password != confirm {
		m.error = "Passwords don't match"
		m.confirmInput.Reset()
		return m, nil
	}

	v, phrase, err := vault.Create(vaultPath, password)
	if err != nil {
		// Check for keyring-specific error
		if strings.Contains(err.Error(), "keyring") {
			m.error = "Keyring access failed - check system permissions"
		} else {
			m.error = "Failed to create vault: " + err.Error()
		}
		return m, nil
	}
	return m, func() tea.Msg { return VaultCreatedMsg{Vault: v, RecoveryPhrase: phrase} }
}

func (m *CreationModel) View(width, height int) string {
	contentWidth := 50

	var b strings.Builder

	// Header
	b.WriteString(RenderHeader("VAULT", "Setup", contentWidth))
	b.WriteString("\n\n")

	// Section
	b.WriteString(RenderSectionHeader("CREATE VAULT"))
	b.WriteString("\n\n")

	// Password field
	label1 := DimStyle.Render("Master Password")
	if m.focusIndex == 0 {
		label1 = TitleStyle.Render("Master Password")
	}
	b.WriteString(label1)
	b.WriteString("\n")
	b.WriteString("  " + m.passwordInput.View())
	if m.focusIndex == 0 {
		b.WriteString(TitleStyle.Render("█"))
	}
	b.WriteString("\n")

	// Strength
	if m.passwordInput.Value() != "" {
		bar := RenderProgressBar(m.passwordStrength.Percentage(), 15)
		strength := RenderPasswordStrength(int(m.passwordStrength))
		b.WriteString("  " + bar + " " + strength)
		b.WriteString("\n")
	}
	b.WriteString("\n")

	// Confirm field
	label2 := DimStyle.Render("Confirm Password")
	if m.focusIndex == 1 {
		label2 = TitleStyle.Render("Confirm Password")
	}
	b.WriteString(label2)
	b.WriteString("\n")
	b.WriteString("  " + m.confirmInput.View())
	if m.focusIndex == 1 {
		b.WriteString(TitleStyle.Render("█"))
	}
	b.WriteString("\n\n")

	// Info
	b.WriteString(DimStyle.Render("    A recovery phrase will be generated for backup."))
	b.WriteString("\n")
	b.WriteString(DimStyle.Render("    Remember your password - there is no reset option."))
	b.WriteString("\n")

	// Error
	if m.error != "" {
		b.WriteString("\n")
		b.WriteString("    " + ErrorStyle.Render(m.error))
	}

	// Bottom bar
	b.WriteString("\n\n")
	b.WriteString(RenderBottomBar([][]string{
		{"Next", "tab"},
		{"Create", "enter"},
		{"Quit", "esc"},
	}, contentWidth))

	return centerContent(b.String(), width, height)
}
