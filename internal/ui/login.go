// Package ui provides the TUI interface for the password manager.
package ui

import (
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/batterdaysahead/cipher0/internal/crypto"
	"github.com/batterdaysahead/cipher0/internal/vault"
)

type LoginModel struct {
	passwordInput   textinput.Model
	error           string
	keyringMismatch bool // True if keyring is missing or doesn't match vault
}

// NewLoginModelWithVault creates a login model and checks keyring fingerprint match.
func NewLoginModelWithVault(vaultPath string) *LoginModel {
	ti := textinput.New()
	ti.Placeholder = ""
	ti.Focus()
	ti.EchoMode = textinput.EchoPassword
	ti.EchoCharacter = '•'
	ti.Width = 40
	ti.Prompt = ""
	ti.PlaceholderStyle = InputPlaceholderStyle
	ti.TextStyle = lipgloss.NewStyle().Foreground(ColorWhite)

	// Check if current keyring matches vault's fingerprint
	keyringMismatch := false
	db, err := vault.LoadDatabase(vaultPath)
	if err == nil {
		currentFingerprint := crypto.GetKeyringFingerprint()
		keyringMismatch = db.RequiresRecoveryPhrase(currentFingerprint)
	}

	return &LoginModel{
		passwordInput:   ti,
		keyringMismatch: keyringMismatch,
	}
}

func (m *LoginModel) Init() tea.Cmd { return textinput.Blink }

func (m *LoginModel) Update(msg tea.Msg, vaultPath string) (*LoginModel, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyEnter:
			password := m.passwordInput.Value()
			if password == "" {
				m.error = "Password required"
				return m, nil
			}
			v, err := vault.UnlockWithPassword(vaultPath, password)
			if err != nil {
				if m.keyringMismatch {
					m.error = "Keyring mismatch - use recovery phrase"
				} else {
					m.error = "Invalid password"
				}
				m.passwordInput.Reset()
				return m, nil
			}
			return m, func() tea.Msg { return VaultUnlockedMsg{Vault: v} }
		case tea.KeyTab:
			return m, NavigateTo(ScreenRecoveryInput, nil)
		case tea.KeyEsc, tea.KeyCtrlC:
			return m, tea.Quit
		}
	}

	m.passwordInput, cmd = m.passwordInput.Update(msg)
	return m, cmd
}

func (m *LoginModel) View(width, height int) string {
	contentWidth := 50

	var b strings.Builder

	// Header
	b.WriteString(RenderHeader("VAULT", "Login", contentWidth))
	b.WriteString("\n\n")

	// Keyring warning - show prominently at top if keyring mismatch
	if m.keyringMismatch {
		b.WriteString(WarningStyle.Render("    ⚠ Keyring mismatch detected"))
		b.WriteString("\n")
		b.WriteString(DimStyle.Render("    Password login will fail. Use recovery phrase (Tab)."))
		b.WriteString("\n\n")
	}

	// Section
	b.WriteString(RenderSectionHeader("UNLOCK"))
	b.WriteString("\n\n")

	// Password input
	b.WriteString(DimStyle.Render("Master Password"))
	b.WriteString("\n\n")

	// Input field
	b.WriteString("    " + m.passwordInput.View() + TitleStyle.Render("█"))
	b.WriteString("\n\n")

	// Info
	b.WriteString(DimStyle.Render("    Your vault is protected with AES-256-GCM encryption."))
	b.WriteString("\n")
	b.WriteString(DimStyle.Render("    If you forgot your password, use recovery phrase."))
	b.WriteString("\n")

	// Error
	if m.error != "" {
		b.WriteString("\n")
		b.WriteString("    " + ErrorStyle.Render(m.error))
	}

	// Bottom bar
	b.WriteString("\n\n")
	b.WriteString(RenderBottomBar([][]string{
		{"Unlock", "enter"},
		{"Recovery", "tab"},
		{"Quit", "esc"},
	}, contentWidth))

	return centerContent(b.String(), width, height)
}
