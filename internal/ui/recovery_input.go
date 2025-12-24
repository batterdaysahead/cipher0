// Package ui provides the TUI interface for the password manager.
package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/batterdaysahead/cipher0/internal/crypto"
	"github.com/batterdaysahead/cipher0/internal/vault"
)

type RecoveryInputModel struct {
	inputs            []textinput.Model
	focusIdx          int
	error             string
	isPhraseOnlyVault bool // True when vault has no password (backup file)
}

func NewRecoveryInputModel() *RecoveryInputModel {
	m := &RecoveryInputModel{inputs: make([]textinput.Model, 12)}
	for i := range 12 {
		ti := textinput.New()
		ti.Width = 12
		ti.Prompt = ""
		ti.TextStyle = lipgloss.NewStyle().Foreground(ColorWhite)
		if i == 0 {
			ti.Focus()
		}
		m.inputs[i] = ti
	}
	return m
}

func (m *RecoveryInputModel) Init() tea.Cmd { return textinput.Blink }

func (m *RecoveryInputModel) Update(msg tea.Msg, vaultPath string) (*RecoveryInputModel, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyTab, tea.KeyDown, tea.KeyRight:
			if m.focusIdx < 11 {
				m.inputs[m.focusIdx].Blur()
				m.focusIdx++
				m.inputs[m.focusIdx].Focus()
			}
			return m, nil
		case tea.KeyShiftTab, tea.KeyUp, tea.KeyLeft:
			if m.focusIdx > 0 {
				m.inputs[m.focusIdx].Blur()
				m.focusIdx--
				m.inputs[m.focusIdx].Focus()
			}
			return m, nil
		case tea.KeyEnter:
			return m.tryUnlock(vaultPath)
		case tea.KeyEsc:
			if m.isPhraseOnlyVault {
				return m, tea.Quit
			}
			return m, NavigateTo(ScreenLogin, nil)
		}
		if msg.String() == " " {
			word := strings.TrimSpace(m.inputs[m.focusIdx].Value())
			m.inputs[m.focusIdx].SetValue(word)
			if m.focusIdx < 11 {
				m.inputs[m.focusIdx].Blur()
				m.focusIdx++
				m.inputs[m.focusIdx].Focus()
			}
			return m, nil
		}
	}

	m.inputs[m.focusIdx], cmd = m.inputs[m.focusIdx].Update(msg)
	return m, cmd
}

func (m *RecoveryInputModel) tryUnlock(vaultPath string) (*RecoveryInputModel, tea.Cmd) {
	var words []string
	for _, input := range m.inputs {
		word := strings.TrimSpace(strings.ToLower(input.Value()))
		if word == "" {
			m.error = "Fill in all 12 words"
			return m, nil
		}
		words = append(words, word)
	}

	phrase := strings.Join(words, " ")
	if !crypto.ValidateRecoveryPhrase(phrase) {
		m.error = "Invalid recovery phrase"
		return m, nil
	}

	v, err := vault.UnlockWithPhrase(vaultPath, phrase)
	if err != nil {
		m.error = "Failed to unlock"
		return m, nil
	}
	// Always require new password after phrase unlock
	// This handles both phrase-only vaults and manual recovery (keyring lost, forgot password, etc.)
	return m, func() tea.Msg { return VaultUnlockedMsg{Vault: v, NeedsNewPassword: true} }
}

func (m *RecoveryInputModel) View(width, height int) string {
	contentWidth := 50

	var b strings.Builder

	// Header - different for phrase-only vaults
	if m.isPhraseOnlyVault {
		b.WriteString(RenderHeader("VAULT", "Backup Recovery", contentWidth))
	} else {
		b.WriteString(RenderHeader("VAULT", "Recovery", contentWidth))
	}
	b.WriteString("\n\n")

	// Section
	b.WriteString(RenderSectionHeader("ENTER PHRASE"))
	b.WriteString("\n\n")

	if m.isPhraseOnlyVault {
		b.WriteString(WarningStyle.Render("    ⚠ This vault requires recovery phrase"))
		b.WriteString("\n")
		b.WriteString(DimStyle.Render("    A new password will be set after unlock."))
	} else {
		b.WriteString(DimStyle.Render("    Enter your 12-word recovery phrase:"))
	}
	b.WriteString("\n\n")

	// Words grid - fixed width columns
	leftColStyle := lipgloss.NewStyle().Width(20)
	rightColStyle := lipgloss.NewStyle().Width(20)

	for i := range 6 {
		leftIdx, rightIdx := i, i+6

		// Format numbers with color when focused
		leftNum := fmt.Sprintf("%2d.", leftIdx+1)
		rightNum := fmt.Sprintf("%2d.", rightIdx+1)

		if m.focusIdx == leftIdx {
			leftNum = TitleStyle.Render(leftNum)
		} else {
			leftNum = DimStyle.Render(leftNum)
		}

		if m.focusIdx == rightIdx {
			rightNum = TitleStyle.Render(rightNum)
		} else {
			rightNum = DimStyle.Render(rightNum)
		}

		leftVal := m.inputs[leftIdx].View()
		rightVal := m.inputs[rightIdx].View()
		if m.focusIdx == leftIdx {
			leftVal += TitleStyle.Render("█")
		}
		if m.focusIdx == rightIdx {
			rightVal += TitleStyle.Render("█")
		}

		leftCell := leftNum + " " + leftVal
		rightCell := rightNum + " " + rightVal

		b.WriteString(leftColStyle.Render(leftCell) + rightColStyle.Render(rightCell) + "\n")
	}

	// Error
	if m.error != "" {
		b.WriteString("\n")
		b.WriteString("    " + ErrorStyle.Render(m.error))
	}

	// Bottom bar
	b.WriteString("\n\n")
	if m.isPhraseOnlyVault {
		b.WriteString(RenderBottomBar([][]string{
			{"Next", "tab"},
			{"Unlock", "enter"},
			{"Quit", "esc"},
		}, contentWidth))
	} else {
		b.WriteString(RenderBottomBar([][]string{
			{"Next", "tab"},
			{"Unlock", "enter"},
			{"Back", "esc"},
		}, contentWidth))
	}

	return centerContent(b.String(), width, height)
}
