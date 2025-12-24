// Package ui provides the TUI interface for the password manager.
package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/batterdaysahead/cipher0/internal/config"
	"github.com/batterdaysahead/cipher0/internal/utils"
	"github.com/batterdaysahead/cipher0/internal/vault"
)

type SettingsMode int

const (
	SettingsModeList SettingsMode = iota
	SettingsModeChangePassword
	SettingsModeVerifyPhraseWarning  // Warning confirmation step
	SettingsModeVerifyPhrasePassword // Password verification step
	SettingsModeVerifyPhrase         // Phrase input step
)

type SettingsModel struct {
	config      *config.Config
	vault       *vault.Vault
	selectedIdx int
	mode        SettingsMode
	message     string
	messageType string

	// Password change inputs
	currentPassword     textinput.Model
	newPassword         textinput.Model
	confirmPassword     textinput.Model
	passwordFocus       int
	passwordStrength    utils.PasswordStrength
	passwordErrorFields map[int]bool // Track which password fields have errors

	// For phrase-only vaults (backup files)
	requirePasswordSetup bool // If true, skip current password and use SetNewPassword

	// Verify phrase inputs
	verifyPassword textinput.Model
	phraseInputs   []textinput.Model // 12 word inputs
	phraseFocusIdx int               // Currently focused word input
}

func NewSettingsModel(cfg *config.Config, v *vault.Vault) *SettingsModel {
	m := &SettingsModel{config: cfg, vault: v}
	m.initPasswordInputs()
	m.initVerifyPhraseInputs()
	return m
}

func (m *SettingsModel) initPasswordInputs() {
	m.currentPassword = textinput.New()
	m.currentPassword.Placeholder = ""
	m.currentPassword.EchoMode = textinput.EchoPassword
	m.currentPassword.EchoCharacter = '•'
	m.currentPassword.Width = 30
	m.currentPassword.Prompt = ""
	m.currentPassword.TextStyle = lipgloss.NewStyle().Foreground(ColorWhite)

	m.newPassword = textinput.New()
	m.newPassword.Placeholder = ""
	m.newPassword.EchoMode = textinput.EchoPassword
	m.newPassword.EchoCharacter = '•'
	m.newPassword.Width = 30
	m.newPassword.Prompt = ""
	m.newPassword.TextStyle = lipgloss.NewStyle().Foreground(ColorWhite)

	m.confirmPassword = textinput.New()
	m.confirmPassword.Placeholder = ""
	m.confirmPassword.EchoMode = textinput.EchoPassword
	m.confirmPassword.EchoCharacter = '•'
	m.confirmPassword.Width = 30
	m.confirmPassword.Prompt = ""
	m.confirmPassword.TextStyle = lipgloss.NewStyle().Foreground(ColorWhite)

	m.passwordErrorFields = make(map[int]bool)
}

func (m *SettingsModel) initVerifyPhraseInputs() {
	m.verifyPassword = textinput.New()
	m.verifyPassword.Placeholder = ""
	m.verifyPassword.EchoMode = textinput.EchoPassword
	m.verifyPassword.EchoCharacter = '•'
	m.verifyPassword.Width = 30
	m.verifyPassword.Prompt = ""
	m.verifyPassword.TextStyle = lipgloss.NewStyle().Foreground(ColorWhite)

	// Initialize 12 word inputs for phrase entry
	m.phraseInputs = make([]textinput.Model, 12)
	for i := range 12 {
		ti := textinput.New()
		ti.Width = 12
		ti.Prompt = ""
		ti.TextStyle = lipgloss.NewStyle().Foreground(ColorWhite)
		m.phraseInputs[i] = ti
	}
	m.phraseFocusIdx = 0
}

var settingsItems = []string{"Auto-lock timeout", "Clipboard timeout", "Auto-backup", "Backup reminder", "Password length", "Change Password", "Verify Recovery Phrase", "Back"}

func (m *SettingsModel) Init() tea.Cmd {
	// If password setup is required, go directly to change password mode
	if m.requirePasswordSetup {
		m.mode = SettingsModeChangePassword
		m.initPasswordInputs()
		m.newPassword.Focus()
		m.passwordFocus = 1 // Skip current password, focus on new password
		return textinput.Blink
	}
	return nil
}

func (m *SettingsModel) Update(msg tea.Msg) (*SettingsModel, tea.Cmd) {
	switch m.mode {
	case SettingsModeChangePassword:
		return m.updateChangePassword(msg)
	case SettingsModeVerifyPhraseWarning:
		return m.updateVerifyPhraseWarning(msg)
	case SettingsModeVerifyPhrasePassword:
		return m.updateVerifyPhrasePassword(msg)
	case SettingsModeVerifyPhrase:
		return m.updateVerifyPhrase(msg)
	default:
		return m.updateList(msg)
	}
}

func (m *SettingsModel) updateList(msg tea.Msg) (*SettingsModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		m.message = ""
		switch msg.String() {
		case "j", "down":
			if m.selectedIdx < len(settingsItems)-1 {
				m.selectedIdx++
			}
		case "k", "up":
			if m.selectedIdx > 0 {
				m.selectedIdx--
			}
		case "-", "left", "h":
			m.adjust(-1)
		case "+", "=", "right", "l":
			m.adjust(1)
		case " ":
			if m.selectedIdx == 2 {
				m.config.AutoBackup = !m.config.AutoBackup
				_ = config.Save(m.config)
			}
		case "enter":
			switch m.selectedIdx {
			case 5: // Change Password
				m.mode = SettingsModeChangePassword
				m.initPasswordInputs()
				m.currentPassword.Focus()
				m.passwordFocus = 0
				return m, textinput.Blink
			case 6: // Verify Recovery Phrase
				m.mode = SettingsModeVerifyPhraseWarning
				m.message = ""
				return m, nil
			case 7: // Back
				return m, NavigateTo(ScreenMain, nil)
			}
		case "esc", "q":
			return m, NavigateTo(ScreenMain, nil)
		}
	}
	return m, nil
}

func (m *SettingsModel) updateChangePassword(msg tea.Msg) (*SettingsModel, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		// Clear errors on any key (except enter)
		if msg.Type != tea.KeyEnter {
			m.message = ""
			m.passwordErrorFields = make(map[int]bool)
		}

		switch msg.Type {
		case tea.KeyTab, tea.KeyDown:
			m.blurPasswordInputs()
			m.passwordFocus = (m.passwordFocus + 1) % 3
			m.focusPasswordInput()
			return m, nil
		case tea.KeyShiftTab, tea.KeyUp:
			m.blurPasswordInputs()
			m.passwordFocus = (m.passwordFocus + 2) % 3
			m.focusPasswordInput()
			return m, nil
		case tea.KeyEnter:
			return m.changePassword()
		case tea.KeyEsc:
			if m.requirePasswordSetup {
				// Can't cancel when password setup is required
				m.message = "Password setup required"
				m.messageType = "error"
				return m, nil
			}
			m.mode = SettingsModeList
			m.message = ""
			return m, nil
		}
	}

	switch m.passwordFocus {
	case 0:
		m.currentPassword, cmd = m.currentPassword.Update(msg)
	case 1:
		m.newPassword, cmd = m.newPassword.Update(msg)
		m.passwordStrength = utils.CalculateStrength(m.newPassword.Value())
	case 2:
		m.confirmPassword, cmd = m.confirmPassword.Update(msg)
	}
	return m, cmd
}

func (m *SettingsModel) blurPasswordInputs() {
	m.currentPassword.Blur()
	m.newPassword.Blur()
	m.confirmPassword.Blur()
}

func (m *SettingsModel) focusPasswordInput() {
	switch m.passwordFocus {
	case 0:
		m.currentPassword.Focus()
	case 1:
		m.newPassword.Focus()
	case 2:
		m.confirmPassword.Focus()
	}
}

func (m *SettingsModel) changePassword() (*SettingsModel, tea.Cmd) {
	// Clear previous errors
	m.message = ""
	m.passwordErrorFields = make(map[int]bool)

	current := m.currentPassword.Value()
	newPwd := m.newPassword.Value()
	confirm := m.confirmPassword.Value()

	// Skip current password check for phrase-only vault setup
	if !m.requirePasswordSetup {
		if current == "" {
			m.message = "Current password required"
			m.messageType = "error"
			m.passwordErrorFields[0] = true
			return m, nil
		}
	}
	if newPwd == "" {
		m.message = "New password required"
		m.messageType = "error"
		m.passwordErrorFields[1] = true
		return m, nil
	}
	if len(newPwd) < 8 {
		m.message = "Minimum 8 characters"
		m.messageType = "error"
		m.passwordErrorFields[1] = true
		return m, nil
	}
	if newPwd != confirm {
		m.message = "Passwords don't match"
		m.messageType = "error"
		m.passwordErrorFields[2] = true
		m.confirmPassword.Reset()
		return m, nil
	}

	var err error
	if m.requirePasswordSetup {
		// Use SetNewPassword for phrase-only vaults
		err = m.vault.SetNewPassword(newPwd)
	} else {
		err = m.vault.ChangePassword(current, newPwd)
	}
	if err != nil {
		m.message = "Current password is incorrect"
		m.messageType = "error"
		m.passwordErrorFields[0] = true
		m.currentPassword.Reset()
		return m, nil
	}

	m.requirePasswordSetup = false // Clear flag after successful setup
	m.mode = SettingsModeList
	m.message = "Password set successfully"
	m.messageType = "success"
	// Navigate to main screen after successful password setup
	return m, NavigateTo(ScreenMain, nil)
}

// updateVerifyPhraseWarning handles the warning confirmation step.
func (m *SettingsModel) updateVerifyPhraseWarning(msg tea.Msg) (*SettingsModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "y", "Y", "enter":
			// User confirmed, proceed to password verification
			m.mode = SettingsModeVerifyPhrasePassword
			m.initVerifyPhraseInputs()
			m.verifyPassword.Focus()
			m.message = ""
			return m, textinput.Blink
		case "n", "N", "esc", "q":
			// User cancelled
			m.mode = SettingsModeList
			m.message = ""
			return m, nil
		}
	}
	return m, nil
}

// updateVerifyPhrasePassword handles password verification step.
func (m *SettingsModel) updateVerifyPhrasePassword(msg tea.Msg) (*SettingsModel, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyEnter:
			// Verify the password
			password := m.verifyPassword.Value()
			if password == "" {
				m.message = "Password required"
				m.messageType = "error"
				return m, nil
			}

			// Attempt to verify password by trying to unlock
			err := m.vault.VerifyPassword(password)
			if err != nil {
				m.message = "Incorrect password"
				m.messageType = "error"
				m.verifyPassword.Reset()
				return m, nil
			}

			// Password verified, proceed to phrase input
			m.mode = SettingsModeVerifyPhrase
			m.verifyPassword.Blur()
			// Focus first phrase word input
			m.phraseFocusIdx = 0
			m.phraseInputs[0].Focus()
			m.message = ""
			return m, textinput.Blink
		case tea.KeyEsc:
			m.mode = SettingsModeList
			m.message = ""
			m.verifyPassword.Reset()
			return m, nil
		}
	}

	m.verifyPassword, cmd = m.verifyPassword.Update(msg)
	return m, cmd
}

// updateVerifyPhrase handles phrase input and verification.
func (m *SettingsModel) updateVerifyPhrase(msg tea.Msg) (*SettingsModel, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyTab, tea.KeyDown, tea.KeyRight:
			// Navigate to next word
			if m.phraseFocusIdx < 11 {
				m.phraseInputs[m.phraseFocusIdx].Blur()
				m.phraseFocusIdx++
				m.phraseInputs[m.phraseFocusIdx].Focus()
			}
			return m, nil
		case tea.KeyShiftTab, tea.KeyUp, tea.KeyLeft:
			// Navigate to previous word
			if m.phraseFocusIdx > 0 {
				m.phraseInputs[m.phraseFocusIdx].Blur()
				m.phraseFocusIdx--
				m.phraseInputs[m.phraseFocusIdx].Focus()
			}
			return m, nil
		case tea.KeyEnter:
			// Collect all words and verify the phrase
			var words []string
			for _, input := range m.phraseInputs {
				word := strings.TrimSpace(strings.ToLower(input.Value()))
				if word == "" {
					m.message = "Fill in all 12 words"
					m.messageType = "error"
					return m, nil
				}
				words = append(words, word)
			}

			phrase := strings.Join(words, " ")

			// Attempt to verify phrase by trying to unlock with it
			err := m.vault.VerifyPhrase(phrase)
			if err != nil {
				m.message = "Incorrect recovery phrase"
				m.messageType = "error"
				return m, nil
			}

			// Phrase verified successfully
			m.mode = SettingsModeList
			m.resetPhraseInputs()
			m.message = "Recovery phrase verified successfully!"
			m.messageType = "success"
			return m, nil
		case tea.KeyEsc:
			m.mode = SettingsModeList
			m.message = ""
			m.resetPhraseInputs()
			return m, nil
		}
		// Handle space to move to next word (like recovery input)
		if msg.String() == " " {
			word := strings.TrimSpace(m.phraseInputs[m.phraseFocusIdx].Value())
			m.phraseInputs[m.phraseFocusIdx].SetValue(word)
			if m.phraseFocusIdx < 11 {
				m.phraseInputs[m.phraseFocusIdx].Blur()
				m.phraseFocusIdx++
				m.phraseInputs[m.phraseFocusIdx].Focus()
			}
			return m, nil
		}
	}

	m.phraseInputs[m.phraseFocusIdx], cmd = m.phraseInputs[m.phraseFocusIdx].Update(msg)
	return m, cmd
}

// resetPhraseInputs resets all phrase word inputs.
func (m *SettingsModel) resetPhraseInputs() {
	for i := range m.phraseInputs {
		m.phraseInputs[i].Reset()
		m.phraseInputs[i].Blur()
	}
	m.phraseFocusIdx = 0
}

func (m *SettingsModel) adjust(delta int) {
	switch m.selectedIdx {
	case 0:
		m.config.AutoLockTimeout += delta * 60
		if m.config.AutoLockTimeout < 60 {
			m.config.AutoLockTimeout = 60
		}
		if m.config.AutoLockTimeout > 3600 {
			m.config.AutoLockTimeout = 3600
		}
	case 1:
		m.config.ClipboardTimeout += delta * 5
		if m.config.ClipboardTimeout < 5 {
			m.config.ClipboardTimeout = 5
		}
		if m.config.ClipboardTimeout > 120 {
			m.config.ClipboardTimeout = 120
		}
	case 3:
		m.config.BackupReminderDays += delta
		if m.config.BackupReminderDays < 1 {
			m.config.BackupReminderDays = 1
		}
		if m.config.BackupReminderDays > 90 {
			m.config.BackupReminderDays = 90
		}
	case 4:
		m.config.PasswordGenerator.DefaultLength += delta
		if m.config.PasswordGenerator.DefaultLength < 8 {
			m.config.PasswordGenerator.DefaultLength = 8
		}
		if m.config.PasswordGenerator.DefaultLength > 64 {
			m.config.PasswordGenerator.DefaultLength = 64
		}
	}
	_ = config.Save(m.config)
}

func (m *SettingsModel) View(width, height int) string {
	switch m.mode {
	case SettingsModeChangePassword:
		return m.viewChangePassword(width, height)
	case SettingsModeVerifyPhraseWarning:
		return m.viewVerifyPhraseWarning(width, height)
	case SettingsModeVerifyPhrasePassword:
		return m.viewVerifyPhrasePassword(width, height)
	case SettingsModeVerifyPhrase:
		return m.viewVerifyPhrase(width, height)
	default:
		return m.viewList(width, height)
	}
}

func (m *SettingsModel) viewList(width, height int) string {
	contentWidth := 55

	var b strings.Builder

	// Header
	b.WriteString(RenderHeader("VAULT", "Settings", contentWidth))
	b.WriteString("\n\n")

	// Section
	b.WriteString(RenderSectionHeader("SETTINGS"))
	b.WriteString("\n\n")

	values := []string{
		fmt.Sprintf("%d min", m.config.AutoLockTimeout/60),
		fmt.Sprintf("%d sec", m.config.ClipboardTimeout),
		map[bool]string{true: "on", false: "off"}[m.config.AutoBackup],
		fmt.Sprintf("%d days", m.config.BackupReminderDays),
		fmt.Sprintf("%d chars", m.config.PasswordGenerator.DefaultLength),
		"",
		"",
		"",
	}

	for i, item := range settingsItems {
		b.WriteString(RenderListItem(fmt.Sprintf("%-22s", item), i == m.selectedIdx))
		if values[i] != "" {
			b.WriteString("  " + ValueStyle.Render(values[i]))
		}
		b.WriteString("\n")
	}

	// Message
	if m.message != "" {
		b.WriteString("\n")
		if m.messageType == "success" {
			b.WriteString(SuccessStyle.Render("✓ " + m.message))
		} else {
			b.WriteString(ErrorStyle.Render(m.message))
		}
	}

	// Bottom bar
	b.WriteString("\n\n")
	b.WriteString(RenderBottomBar([][]string{
		{"Navigate", "↑↓"},
		{"Adjust", "←→"},
		{"Select", "enter"},
		{"Back", "esc"},
	}, contentWidth))

	return centerContent(b.String(), width, height)
}

func (m *SettingsModel) viewChangePassword(width, height int) string {
	contentWidth := 50

	var b strings.Builder

	// Header
	if m.requirePasswordSetup {
		b.WriteString(RenderHeader("VAULT", "Password Setup", contentWidth))
		b.WriteString("\n\n")
		b.WriteString(RenderSectionHeader("SET NEW PASSWORD"))
	} else {
		b.WriteString(RenderHeader("VAULT", "Password", contentWidth))
		b.WriteString("\n\n")
		b.WriteString(RenderSectionHeader("CHANGE PASSWORD"))
	}
	b.WriteString("\n\n")

	// Current password (skip for phrase-only vault setup)
	if !m.requirePasswordSetup {
		var label1 string
		if m.passwordErrorFields[0] {
			label1 = ErrorStyle.Render("Current Password")
		} else if m.passwordFocus == 0 {
			label1 = TitleStyle.Render("Current Password")
		} else {
			label1 = DimStyle.Render("Current Password")
		}
		b.WriteString(label1)
		b.WriteString("\n")
		b.WriteString("  " + m.currentPassword.View())
		if m.passwordFocus == 0 {
			b.WriteString(TitleStyle.Render("█"))
		}
		b.WriteString("\n\n")
	}

	// New password
	var label2 string
	if m.passwordErrorFields[1] {
		label2 = ErrorStyle.Render("New Password")
	} else if m.passwordFocus == 1 {
		label2 = TitleStyle.Render("New Password")
	} else {
		label2 = DimStyle.Render("New Password")
	}
	b.WriteString(label2)
	b.WriteString("\n")
	b.WriteString("  " + m.newPassword.View())
	if m.passwordFocus == 1 {
		b.WriteString(TitleStyle.Render("█"))
	}
	b.WriteString("\n")

	// Strength indicator
	if m.newPassword.Value() != "" {
		bar := RenderProgressBar(m.passwordStrength.Percentage(), 15)
		strength := RenderPasswordStrength(int(m.passwordStrength))
		b.WriteString("  " + bar + " " + strength + "\n")
	}
	b.WriteString("\n")

	// Confirm password
	var label3 string
	if m.passwordErrorFields[2] {
		label3 = ErrorStyle.Render("Confirm Password")
	} else if m.passwordFocus == 2 {
		label3 = TitleStyle.Render("Confirm Password")
	} else {
		label3 = DimStyle.Render("Confirm Password")
	}
	b.WriteString(label3)
	b.WriteString("\n")
	b.WriteString("  " + m.confirmPassword.View())
	if m.passwordFocus == 2 {
		b.WriteString(TitleStyle.Render("█"))
	}
	b.WriteString("\n")

	// Error
	if m.message != "" && m.messageType == "error" {
		b.WriteString("\n")
		b.WriteString(ErrorStyle.Render(m.message))
	}

	// Bottom bar
	b.WriteString("\n\n")
	b.WriteString(RenderBottomBar([][]string{
		{"Next", "tab"},
		{"Save", "enter"},
		{"Cancel", "esc"},
	}, contentWidth))

	return centerContent(b.String(), width, height)
}

// viewVerifyPhraseWarning shows the warning confirmation screen.
func (m *SettingsModel) viewVerifyPhraseWarning(width, height int) string {
	contentWidth := 60

	var b strings.Builder

	// Header
	b.WriteString(RenderHeader("VAULT", "Verify Phrase", contentWidth))
	b.WriteString("\n\n")

	// Warning section
	b.WriteString(RenderSectionHeader("⚠ WARNING"))
	b.WriteString("\n\n")

	// Warning message
	warningStyle := lipgloss.NewStyle().Foreground(ColorYellow)
	b.WriteString(warningStyle.Render("You are about to verify your recovery phrase."))
	b.WriteString("\n\n")

	b.WriteString(DimStyle.Render("This feature lets you confirm you have correctly"))
	b.WriteString("\n")
	b.WriteString(DimStyle.Render("written down your 12-word recovery phrase."))
	b.WriteString("\n\n")

	b.WriteString(ErrorStyle.Render("IMPORTANT:"))
	b.WriteString("\n")
	b.WriteString(DimStyle.Render("• Never share your recovery phrase with anyone"))
	b.WriteString("\n")
	b.WriteString(DimStyle.Render("• Never enter it on any website or app"))
	b.WriteString("\n")
	b.WriteString(DimStyle.Render("• Ensure no one is watching your screen"))
	b.WriteString("\n\n")

	b.WriteString(TitleStyle.Render("Do you want to proceed?"))
	b.WriteString("\n\n")

	// Bottom bar
	b.WriteString(RenderBottomBar([][]string{
		{"Yes", "y"},
		{"No", "n"},
		{"Cancel", "esc"},
	}, contentWidth))

	return centerContent(b.String(), width, height)
}

// viewVerifyPhrasePassword shows the password verification screen.
func (m *SettingsModel) viewVerifyPhrasePassword(width, height int) string {
	contentWidth := 50

	var b strings.Builder

	// Header
	b.WriteString(RenderHeader("VAULT", "Verify Phrase", contentWidth))
	b.WriteString("\n\n")

	// Section
	b.WriteString(RenderSectionHeader("VERIFY IDENTITY"))
	b.WriteString("\n\n")

	b.WriteString(DimStyle.Render("Enter your master password to continue:"))
	b.WriteString("\n\n")

	// Password input
	label := TitleStyle.Render("Master Password")
	b.WriteString(label)
	b.WriteString("\n")
	b.WriteString("  " + m.verifyPassword.View())
	b.WriteString(TitleStyle.Render("█"))
	b.WriteString("\n")

	// Error
	if m.message != "" && m.messageType == "error" {
		b.WriteString("\n")
		b.WriteString(ErrorStyle.Render(m.message))
	}

	// Bottom bar
	b.WriteString("\n\n")
	b.WriteString(RenderBottomBar([][]string{
		{"Verify", "enter"},
		{"Cancel", "esc"},
	}, contentWidth))

	return centerContent(b.String(), width, height)
}

// viewVerifyPhrase shows the phrase input screen with 12-word grid.
func (m *SettingsModel) viewVerifyPhrase(width, height int) string {
	contentWidth := 50

	var b strings.Builder

	// Header
	b.WriteString(RenderHeader("VAULT", "Verify Phrase", contentWidth))
	b.WriteString("\n\n")

	// Section
	b.WriteString(RenderSectionHeader("ENTER PHRASE"))
	b.WriteString("\n\n")

	b.WriteString(DimStyle.Render("    Enter your 12-word recovery phrase:"))
	b.WriteString("\n\n")

	// Words grid - fixed width columns (matching recovery_input.go)
	leftColStyle := lipgloss.NewStyle().Width(20)
	rightColStyle := lipgloss.NewStyle().Width(20)

	for i := range 6 {
		leftIdx, rightIdx := i, i+6

		// Format numbers with color when focused
		leftNum := fmt.Sprintf("%2d.", leftIdx+1)
		rightNum := fmt.Sprintf("%2d.", rightIdx+1)

		if m.phraseFocusIdx == leftIdx {
			leftNum = TitleStyle.Render(leftNum)
		} else {
			leftNum = DimStyle.Render(leftNum)
		}

		if m.phraseFocusIdx == rightIdx {
			rightNum = TitleStyle.Render(rightNum)
		} else {
			rightNum = DimStyle.Render(rightNum)
		}

		leftVal := m.phraseInputs[leftIdx].View()
		rightVal := m.phraseInputs[rightIdx].View()
		if m.phraseFocusIdx == leftIdx {
			leftVal += TitleStyle.Render("█")
		}
		if m.phraseFocusIdx == rightIdx {
			rightVal += TitleStyle.Render("█")
		}

		leftCell := leftNum + " " + leftVal
		rightCell := rightNum + " " + rightVal

		b.WriteString(leftColStyle.Render(leftCell) + rightColStyle.Render(rightCell) + "\n")
	}

	// Message
	if m.message != "" {
		b.WriteString("\n")
		if m.messageType == "success" {
			b.WriteString("    " + SuccessStyle.Render("✓ "+m.message))
		} else {
			b.WriteString("    " + ErrorStyle.Render(m.message))
		}
	}

	// Bottom bar
	b.WriteString("\n\n")
	b.WriteString(RenderBottomBar([][]string{
		{"Next", "tab"},
		{"Verify", "enter"},
		{"Cancel", "esc"},
	}, contentWidth))

	return centerContent(b.String(), width, height)
}
