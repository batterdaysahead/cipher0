// Package ui provides the TUI interface for the password manager.
package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/batterdaysahead/cipher0/internal/totp"
	"github.com/batterdaysahead/cipher0/internal/utils"
	"github.com/batterdaysahead/cipher0/internal/vault"
)

type EntryField int

const (
	FieldTitle EntryField = iota
	FieldUsername
	FieldPassword
	FieldURL
	FieldTOTP
	FieldNotes
)

type EntryModel struct {
	vault        *vault.Vault
	clipboard    *utils.ClipboardManager
	entry        *vault.Entry
	isNew        bool
	focusIdx     EntryField
	showPassword bool
	error        string
	errorFields  map[EntryField]bool // Track which fields have errors

	titleInput, usernameInput, passwordInput textinput.Model
	urlInput, totpInput, notesInput          textinput.Model
}

func NewEntryModel(v *vault.Vault, entry *vault.Entry, clip *utils.ClipboardManager) *EntryModel {
	m := &EntryModel{vault: v, clipboard: clip, isNew: entry == nil}

	if entry == nil {
		m.entry = vault.NewEntry("")
	} else {
		m.entry = &vault.Entry{
			ID: entry.ID, Title: entry.Title, Username: entry.Username,
			Password: entry.Password, URL: entry.URL, Notes: entry.Notes,
			TOTPSecret: entry.TOTPSecret,
			Created:    entry.Created, Updated: entry.Updated,
		}
	}

	m.titleInput = m.makeInput(m.entry.Title)
	m.titleInput.Focus()
	m.usernameInput = m.makeInput(m.entry.Username)
	m.passwordInput = m.makeInput(m.entry.Password)
	m.passwordInput.EchoMode = textinput.EchoPassword
	m.passwordInput.EchoCharacter = '•'
	m.urlInput = m.makeInput(m.entry.URL)
	m.totpInput = m.makeInput(m.entry.TOTPSecret)
	m.notesInput = m.makeInput(m.entry.Notes)

	m.errorFields = make(map[EntryField]bool)

	return m
}

func (m *EntryModel) makeInput(value string) textinput.Model {
	ti := textinput.New()
	ti.SetValue(value)
	ti.Width = 35
	ti.Prompt = ""
	ti.PlaceholderStyle = InputPlaceholderStyle
	ti.TextStyle = lipgloss.NewStyle().Foreground(ColorWhite)
	return ti
}

func (m *EntryModel) Init() tea.Cmd { return textinput.Blink }

func (m *EntryModel) Update(msg tea.Msg) (*EntryModel, tea.Cmd) {
	switch msg := msg.(type) {
	case PasswordGeneratedMsg:
		m.passwordInput.SetValue(msg.Password)
		return m, nil
	case tea.KeyMsg:
		// Clear errors on any typing (except save)
		if msg.Type != tea.KeyCtrlS {
			m.error = ""
			m.errorFields = make(map[EntryField]bool)
		}

		switch msg.Type {
		case tea.KeyTab, tea.KeyDown:
			m.blur()
			m.focusIdx = (m.focusIdx + 1) % 6
			m.focus()
		case tea.KeyShiftTab, tea.KeyUp:
			m.blur()
			m.focusIdx = (m.focusIdx + 5) % 6
			m.focus()
		case tea.KeyCtrlS:
			return m.save()
		case tea.KeyCtrlG:
			pwd, _ := utils.GeneratePassword(utils.DefaultGeneratorOptions())
			return m, func() tea.Msg { return PasswordGeneratedMsg{Password: pwd} }
		case tea.KeyCtrlV:
			if m.focusIdx == FieldPassword {
				m.showPassword = !m.showPassword
				if m.showPassword {
					m.passwordInput.EchoMode = textinput.EchoNormal
				} else {
					m.passwordInput.EchoMode = textinput.EchoPassword
				}
			}
		case tea.KeyEsc:
			return m, NavigateTo(ScreenMain, nil)
		}
	}
	m.updateInput(msg)
	return m, nil
}

func (m *EntryModel) blur() {
	inputs := []*textinput.Model{&m.titleInput, &m.usernameInput, &m.passwordInput, &m.urlInput, &m.totpInput, &m.notesInput}
	inputs[m.focusIdx].Blur()
}

func (m *EntryModel) focus() {
	inputs := []*textinput.Model{&m.titleInput, &m.usernameInput, &m.passwordInput, &m.urlInput, &m.totpInput, &m.notesInput}
	inputs[m.focusIdx].Focus()
}

func (m *EntryModel) updateInput(msg tea.Msg) {
	switch m.focusIdx {
	case FieldTitle:
		m.titleInput, _ = m.titleInput.Update(msg)
	case FieldUsername:
		m.usernameInput, _ = m.usernameInput.Update(msg)
	case FieldPassword:
		m.passwordInput, _ = m.passwordInput.Update(msg)
	case FieldURL:
		m.urlInput, _ = m.urlInput.Update(msg)
	case FieldTOTP:
		m.totpInput, _ = m.totpInput.Update(msg)
	case FieldNotes:
		m.notesInput, _ = m.notesInput.Update(msg)
	}
}

func (m *EntryModel) save() (*EntryModel, tea.Cmd) {
	// Clear previous errors
	m.error = ""
	m.errorFields = make(map[EntryField]bool)

	title := strings.TrimSpace(m.titleInput.Value())
	if title == "" {
		m.error = "Title required"
		m.errorFields[FieldTitle] = true
		return m, nil
	}

	username := strings.TrimSpace(m.usernameInput.Value())
	if username == "" {
		m.error = "Username/Email required"
		m.errorFields[FieldUsername] = true
		return m, nil
	}

	password := m.passwordInput.Value()
	if password == "" {
		m.error = "Password required"
		m.errorFields[FieldPassword] = true
		return m, nil
	}

	m.entry.Title = title
	m.entry.Username = username
	m.entry.Password = password
	m.entry.URL = strings.TrimSpace(m.urlInput.Value())
	m.entry.TOTPSecret = strings.TrimSpace(m.totpInput.Value())
	m.entry.Notes = m.notesInput.Value()

	if m.entry.TOTPSecret != "" && !totp.ValidateSecret(m.entry.TOTPSecret) {
		m.error = "Invalid TOTP secret"
		m.errorFields[FieldTOTP] = true
		return m, nil
	}

	var err error
	if m.isNew {
		err = m.vault.AddEntry(m.entry)
	} else {
		err = m.vault.UpdateEntry(m.entry)
	}
	if err != nil {
		m.error = err.Error()
		return m, nil
	}
	_ = m.vault.Save()

	return m, tea.Batch(
		func() tea.Msg { return EntrySavedMsg{Entry: m.entry, IsNew: m.isNew} },
		NavigateTo(ScreenMain, nil),
	)
}

func (m *EntryModel) View(width, height int) string {
	contentWidth := 55

	section := "New"
	if !m.isNew {
		section = "Edit"
	}

	var b strings.Builder

	// Header
	b.WriteString(RenderHeader("VAULT", section, contentWidth))
	b.WriteString("\n\n")

	// Section
	title := "NEW ACCOUNT"
	if !m.isNew {
		title = m.entry.Title
	}
	b.WriteString(RenderSectionHeader(title))
	b.WriteString("\n\n")

	// Form fields
	fields := []struct {
		label string
		input *textinput.Model
		idx   EntryField
	}{
		{"Title", &m.titleInput, FieldTitle},
		{"Username", &m.usernameInput, FieldUsername},
		{"Password", &m.passwordInput, FieldPassword},
		{"URL", &m.urlInput, FieldURL},
		{"TOTP", &m.totpInput, FieldTOTP},
		{"Notes", &m.notesInput, FieldNotes},
	}

	labelWidth := 12
	for _, f := range fields {
		label := f.label
		if f.idx == FieldPassword && m.showPassword {
			label = "Password 👁"
		}

		// Pad label to fixed width
		paddedLabel := fmt.Sprintf("%-*s", labelWidth, label)

		// Show error styling if field has an error
		if m.errorFields[f.idx] {
			b.WriteString(ErrorStyle.Render(paddedLabel))
		} else if m.focusIdx == f.idx {
			b.WriteString(TitleStyle.Render(paddedLabel))
		} else {
			b.WriteString(DimStyle.Render(paddedLabel))
		}
		b.WriteString(f.input.View())
		if m.focusIdx == f.idx {
			b.WriteString(TitleStyle.Render("█"))
		}
		b.WriteString("\n\n")

		// Show TOTP code if valid
		if f.idx == FieldTOTP {
			if secret := m.totpInput.Value(); secret != "" && totp.ValidateSecret(secret) {
				if code, remaining, err := totp.GenerateCode(secret); err == nil {
					style := TOTPCodeStyle
					if remaining <= 5 {
						style = TOTPTimerUrgentStyle
					}
					b.WriteString(fmt.Sprintf("%-*s", labelWidth, "") + style.Render(totp.FormatCode(code)) + DimStyle.Render(fmt.Sprintf(" %ds", remaining)) + "\n")
					b.WriteString("\n")
				}
			}
		}
	}

	// Error
	if m.error != "" {
		b.WriteString("\n")
		b.WriteString("    " + ErrorStyle.Render(m.error))
	}

	// Bottom bar
	b.WriteString("\n\n")
	b.WriteString(RenderBottomBar([][]string{
		{"Next", "tab"},
		{"Save", "ctrl+s"},
		{"Generate", "ctrl+g"},
		{"Cancel", "esc"},
	}, contentWidth))

	return centerContent(b.String(), width, height)
}
