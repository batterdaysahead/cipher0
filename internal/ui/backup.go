// Package ui provides the TUI interface for the password manager.
package ui

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/batterdaysahead/cipher0/internal/config"
	"github.com/batterdaysahead/cipher0/internal/vault"
)

type BackupModel struct {
	vault       *vault.Vault
	selectedIdx int
	message     string
	messageType string
}

var backupItems = []string{"Export encrypted backup", "Export plaintext (danger)", "Back"}

func NewBackupModel(v *vault.Vault) *BackupModel {
	return &BackupModel{vault: v}
}

func (m *BackupModel) Init() tea.Cmd { return nil }

func (m *BackupModel) Update(msg tea.Msg) (*BackupModel, tea.Cmd) {
	switch msg := msg.(type) {
	case BackupCompletedMsg:
		m.message = "Saved: " + filepath.Base(msg.Path)
		m.messageType = "success"
	case BackupFailedMsg:
		m.message = msg.Error
		m.messageType = "error"
	case tea.KeyMsg:
		switch msg.String() {
		case "j", "down":
			if m.selectedIdx < len(backupItems)-1 {
				m.selectedIdx++
			}
		case "k", "up":
			if m.selectedIdx > 0 {
				m.selectedIdx--
			}
		case "enter":
			switch m.selectedIdx {
			case 0:
				return m, m.createBackup()
			case 1:
				return m, RequestConfirmation("Warning", "Create unencrypted backup?", m.createPlaintext(), nil)
			case 2:
				return m, NavigateTo(ScreenMain, nil)
			}
		case "esc", "q":
			return m, NavigateTo(ScreenMain, nil)
		}
	}
	return m, nil
}

func (m *BackupModel) createBackup() tea.Cmd {
	dir := config.DefaultBackupDir()
	filename := vault.GenerateBackupFilename("vault")
	path := filepath.Join(dir, filename)
	return func() tea.Msg {
		if err := m.vault.ExportEncryptedBackup(path); err != nil {
			return BackupFailedMsg{Error: err.Error()}
		}
		return BackupCompletedMsg{Path: path}
	}
}

func (m *BackupModel) createPlaintext() tea.Cmd {
	return func() tea.Msg {
		dir := config.DefaultBackupDir()
		filename := fmt.Sprintf("vault_plaintext_%s.json", time.Now().Format("2006-01-02_150405"))
		path := filepath.Join(dir, filename)
		if err := m.vault.ExportPlaintext(path); err != nil {
			return BackupFailedMsg{Error: err.Error()}
		}
		return BackupCompletedMsg{Path: path}
	}
}

func (m *BackupModel) View(width, height int) string {
	contentWidth := 50

	var b strings.Builder

	// Header
	b.WriteString(RenderHeader("VAULT", "Backup", contentWidth))
	b.WriteString("\n\n")

	// Section
	b.WriteString(RenderSectionHeader("BACKUP"))
	b.WriteString("\n\n")

	for i, item := range backupItems {
		b.WriteString(RenderListItem(item, i == m.selectedIdx))
		b.WriteString("\n")
	}

	b.WriteString("\n")
	b.WriteString(DimStyle.Render("    Backup restore requires 12-word recovery phrase."))
	b.WriteString("\n")
	b.WriteString(DimStyle.Render("    Plaintext exports are for migration only."))

	// Message
	if m.message != "" {
		b.WriteString("\n\n")
		if m.messageType == "success" {
			b.WriteString("    " + SuccessStyle.Render("✓ "+m.message))
		} else {
			b.WriteString("    " + ErrorStyle.Render(m.message))
		}
	}

	// Bottom bar
	b.WriteString("\n\n")
	b.WriteString(RenderBottomBar([][]string{
		{"Navigate", "↑↓"},
		{"Select", "enter"},
		{"Back", "esc"},
	}, contentWidth))

	return centerContent(b.String(), width, height)
}
