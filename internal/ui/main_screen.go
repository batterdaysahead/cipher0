// Package ui provides the TUI interface for the password manager.
package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/batterdaysahead/cipher0/internal/totp"
	"github.com/batterdaysahead/cipher0/internal/utils"
	"github.com/batterdaysahead/cipher0/internal/vault"
)

const (
	itemsPerPage         = 10
	notificationDuration = 3 * time.Second
)

type MainModel struct {
	vault            *vault.Vault
	clipboard        *utils.ClipboardManager
	entries          vault.EntryList
	filteredEntries  vault.EntryList
	selectedIdx      int
	currentPage      int
	searchInput      textinput.Model
	searchMode       bool
	message          string
	messageType      string
	passwordRevealed bool
	showQRCode       bool
}

func NewMainModel(v *vault.Vault, clip *utils.ClipboardManager) *MainModel {
	si := textinput.New()
	si.Placeholder = ""
	si.Width = 30
	si.Prompt = ""
	si.PlaceholderStyle = InputPlaceholderStyle
	si.TextStyle = lipgloss.NewStyle().Foreground(ColorWhite)
	m := &MainModel{vault: v, clipboard: clip, searchInput: si}
	m.refreshEntries()
	return m
}

func (m *MainModel) Init() tea.Cmd { return nil }

func (m *MainModel) refreshEntries() {
	m.entries = m.vault.Entries()
	m.applyFilter()
}

func (m *MainModel) applyFilter() {
	if m.searchInput.Value() != "" {
		m.filteredEntries = m.entries.Search(m.searchInput.Value())
	} else {
		m.filteredEntries = m.entries
	}
	if m.selectedIdx >= len(m.filteredEntries) {
		m.selectedIdx = len(m.filteredEntries) - 1
	}
	if m.selectedIdx < 0 {
		m.selectedIdx = 0
	}
	m.currentPage = m.selectedIdx / itemsPerPage
}

// totalPages returns the total number of pages
func (m *MainModel) totalPages() int {
	if len(m.filteredEntries) == 0 {
		return 1
	}
	return (len(m.filteredEntries) + itemsPerPage - 1) / itemsPerPage
}

// pageStart returns the starting index for the current page
func (m *MainModel) pageStart() int {
	return m.currentPage * itemsPerPage
}

// pageEnd returns the ending index (exclusive) for the current page
func (m *MainModel) pageEnd() int {
	return min(m.pageStart()+itemsPerPage, len(m.filteredEntries))
}

func (m *MainModel) Update(msg tea.Msg) (*MainModel, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case TOTPTickMsg:
		return m, TOTPTick()
	case ClearNotificationMsg:
		m.message = ""
		return m, nil
	case EntrySavedMsg:
		m.refreshEntries()
		m.message, m.messageType = "Saved", "success"
		return m, ClearNotificationAfter(notificationDuration)
	case EntryDeletedMsg:
		m.refreshEntries()
		m.message, m.messageType = "Deleted", "success"
		return m, ClearNotificationAfter(notificationDuration)
	case tea.KeyMsg:
		m.message = ""
		// Handle QR code overlay - escape or 'o' closes it
		if m.showQRCode {
			if msg.String() == "esc" || msg.String() == "o" || msg.String() == "enter" {
				m.showQRCode = false
			}
			return m, nil
		}
		if m.searchMode {
			return m.handleSearch(msg)
		}
		switch msg.String() {
		case "q":
			return m, RequestConfirmation("Quit", "Exit application?", tea.Quit, nil)
		case "j", "down":
			if m.selectedIdx < len(m.filteredEntries)-1 {
				m.selectedIdx++
				// Move to next page if needed
				if m.selectedIdx >= m.pageEnd() {
					m.currentPage++
				}
			}
		case "k", "up":
			if m.selectedIdx > 0 {
				m.selectedIdx--
				// Move to previous page if needed
				if m.selectedIdx < m.pageStart() {
					m.currentPage--
				}
			}
		case "[", "left":
			// Previous page
			if m.currentPage > 0 {
				m.currentPage--
				m.selectedIdx = m.pageStart()
			}
		case "]", "right":
			// Next page
			if m.currentPage < m.totalPages()-1 {
				m.currentPage++
				m.selectedIdx = m.pageStart()
			}
		case "ctrl+f":
			m.searchMode = true
			m.searchInput.Focus()
		case "n":
			return m, NavigateTo(ScreenEntry, nil)
		case "enter", "e":
			if len(m.filteredEntries) > 0 {
				return m, NavigateTo(ScreenEntry, m.filteredEntries[m.selectedIdx])
			}
		case "d":
			if len(m.filteredEntries) > 0 {
				e := m.filteredEntries[m.selectedIdx]
				return m, RequestConfirmation("Delete", "Delete "+e.Title+"?", m.delete(e.ID), nil)
			}
		case "r":
			m.passwordRevealed = !m.passwordRevealed
		case "p":
			return m, m.copyPassword()
		case "t":
			return m, m.copyTOTP()
		case "u":
			return m, m.copyUser()
		case "o":
			// Show QR code for TOTP
			if len(m.filteredEntries) > 0 && m.filteredEntries[m.selectedIdx].HasTOTP() {
				m.showQRCode = true
			} else {
				m.message, m.messageType = "No TOTP configured for this entry", "error"
			}
		case "b":
			return m, NavigateTo(ScreenBackup, nil)
		case "s":
			return m, NavigateTo(ScreenSettings, nil)
		case "l":
			return m, func() tea.Msg { return VaultLockedMsg{} }
		case "esc":
			m.searchInput.SetValue("")
			m.applyFilter()
		}
	}
	return m, cmd
}

func (m *MainModel) handleSearch(msg tea.KeyMsg) (*MainModel, tea.Cmd) {
	if msg.Type == tea.KeyEnter || msg.Type == tea.KeyEsc {
		m.searchMode = false
		m.searchInput.Blur()
		m.applyFilter()
		return m, TOTPTick()
	}
	var cmd tea.Cmd
	m.searchInput, cmd = m.searchInput.Update(msg)
	m.applyFilter()
	return m, tea.Batch(cmd, TOTPTick())
}

func (m *MainModel) delete(id string) tea.Cmd {
	return func() tea.Msg {
		_ = m.vault.DeleteEntry(id)
		_ = m.vault.Save()
		return EntryDeletedMsg{EntryID: id}
	}
}

func (m *MainModel) copyUser() tea.Cmd {
	if len(m.filteredEntries) == 0 {
		return nil
	}
	e := m.filteredEntries[m.selectedIdx]
	if e.Username != "" {
		_ = m.clipboard.Copy(e.Username)
		return func() tea.Msg { return ClipboardCopiedMsg{Label: "Username"} }
	}
	return nil
}

func (m *MainModel) copyPassword() tea.Cmd {
	if len(m.filteredEntries) == 0 {
		return nil
	}
	e := m.filteredEntries[m.selectedIdx]
	if e.Password != "" {
		_ = m.clipboard.Copy(e.Password)
		return func() tea.Msg { return ClipboardCopiedMsg{Label: "Password"} }
	}
	return nil
}

func (m *MainModel) copyTOTP() tea.Cmd {
	if len(m.filteredEntries) == 0 {
		return nil
	}
	e := m.filteredEntries[m.selectedIdx]
	if !e.HasTOTP() {
		m.message, m.messageType = "No TOTP configured for this entry", "error"
		return nil
	}
	code, _, err := totp.GenerateCode(e.TOTPSecret)
	if err == nil {
		_ = m.clipboard.Copy(code)
		return func() tea.Msg { return ClipboardCopiedMsg{Label: "TOTP"} }
	}
	m.message, m.messageType = "Failed to generate TOTP code", "error"
	return nil
}

func (m *MainModel) View(width, height int) string {
	contentWidth := max(60, min(90, width-4))

	// Show QR code overlay if active
	if m.showQRCode && len(m.filteredEntries) > 0 {
		return m.renderQRCodeView(width, height, contentWidth)
	}

	var b strings.Builder

	// Header
	b.WriteString(RenderHeader("VAULT", "Main", contentWidth))
	b.WriteString("\n\n")

	// Search bar
	b.WriteString(RenderSearchBar(m.searchInput.Value(), m.searchMode, contentWidth))
	b.WriteString("\n\n")

	// Two-column layout
	leftWidth := 25
	rightWidth := contentWidth - leftWidth - 4

	// Left column: ACCOUNTS list
	var leftCol strings.Builder
	leftCol.WriteString(RenderSectionHeader("ACCOUNTS"))
	leftCol.WriteString("\n\n")

	if len(m.filteredEntries) == 0 {
		leftCol.WriteString(DimStyle.Render("No accounts"))
	} else {
		// Render items for current page only
		start := m.pageStart()
		end := m.pageEnd()

		for i := start; i < end; i++ {
			e := m.filteredEntries[i]
			leftCol.WriteString(RenderListItem(TruncateWithEllipsis(e.Title, 20), i == m.selectedIdx))
			leftCol.WriteString("\n")
		}

		// Show page indicator if more than one page
		if m.totalPages() > 1 {
			leftCol.WriteString("\n")
			leftCol.WriteString(DimStyle.Render(fmt.Sprintf("Page %d/%d", m.currentPage+1, m.totalPages())))
		}
	}

	// Right column: DETAILS
	var rightCol strings.Builder
	rightCol.WriteString(RenderSectionHeader("DETAILS"))
	rightCol.WriteString("\n\n")

	if len(m.filteredEntries) > 0 && m.selectedIdx < len(m.filteredEntries) {
		e := m.filteredEntries[m.selectedIdx]

		// Title
		rightCol.WriteString(TitleStyle.Render(e.Title))
		rightCol.WriteString("\n\n")

		// Details
		if e.Username != "" {
			rightCol.WriteString(RenderDetailRow("Username", e.Username))
			rightCol.WriteString("\n")
		}

		// Password (masked or revealed)
		if e.Password != "" {
			var pwdDisplay string
			if m.passwordRevealed {
				pwdDisplay = e.Password
			} else {
				pwdDisplay = strings.Repeat("•", 12)
			}
			rightCol.WriteString(RenderDetailRow("Password", pwdDisplay))
			rightCol.WriteString("\n")
		}

		if e.URL != "" {
			rightCol.WriteString(RenderDetailRow("URL", e.URL))
			rightCol.WriteString("\n")
		}

		rightCol.WriteString(RenderDetailRow("Created", e.Created.Format("2006-01-02")))
		rightCol.WriteString("\n")

		// TOTP if present
		if e.HasTOTP() {
			code, remaining, _ := totp.GenerateCode(e.TOTPSecret)
			var totpStr string
			if remaining <= 5 {
				totpStr = TOTPTimerUrgentStyle.Render(totp.FormatCode(code)) + DimStyle.Render(fmt.Sprintf(" %ds", remaining))
			} else {
				totpStr = TOTPCodeStyle.Render(totp.FormatCode(code)) + DimStyle.Render(fmt.Sprintf(" %ds", remaining))
			}
			rightCol.WriteString("\n")
			rightCol.WriteString(RenderDetailRow("TOTP", totpStr))
			rightCol.WriteString("\n")
		}

		// Notes
		if e.Notes != "" {
			rightCol.WriteString("\n")
			rightCol.WriteString(SectionStyle.Render("NOTES"))
			rightCol.WriteString("\n\n")
			rightCol.WriteString(DimStyle.Render(e.Notes))
		}
	} else {
		rightCol.WriteString(DimStyle.Render("Select an account"))
	}

	// Join columns
	leftStyle := lipgloss.NewStyle().Width(leftWidth)
	rightStyle := lipgloss.NewStyle().Width(rightWidth).PaddingLeft(3)

	columns := lipgloss.JoinHorizontal(lipgloss.Top,
		leftStyle.Render(leftCol.String()),
		rightStyle.Render(rightCol.String()),
	)

	b.WriteString(columns)

	// Message
	if m.message != "" {
		b.WriteString("\n\n")
		if m.messageType == "success" {
			b.WriteString(SuccessStyle.Render("✓ " + m.message))
		} else {
			b.WriteString(ErrorStyle.Render(m.message))
		}
	}

	// Bottom bar - two rows for more functions
	b.WriteString("\n\n")
	b.WriteString(RenderBottomBar([][]string{
		{"New", "n"},
		{"Edit", "e"},
		{"Delete", "d"},
		{"Reveal", "r"},
		{"Pass", "p"},
		{"User", "u"},
		{"TOTP", "t"},
		{"QR", "o"},
	}, contentWidth))
	b.WriteString("\n\n")
	b.WriteString(RenderBottomBar([][]string{
		{"Prev", "["},
		{"Next", "]"},
		{"Settings", "s"},
		{"Backup", "b"},
		{"Lock", "l"},
		{"Quit", "q"},
	}, contentWidth))

	return centerContent(b.String(), width, height)
}

// renderQRCodeView renders a full-screen QR code view for TOTP setup.
func (m *MainModel) renderQRCodeView(width, height, contentWidth int) string {
	e := m.filteredEntries[m.selectedIdx]

	var b strings.Builder

	// Header
	b.WriteString(RenderHeader("QR CODE", "TOTP Setup", contentWidth))
	b.WriteString("\n\n")

	// Entry title
	b.WriteString(TitleStyle.Render(e.Title))
	b.WriteString("\n")
	if e.Username != "" {
		b.WriteString(DimStyle.Render(e.Username))
	}
	b.WriteString("\n\n")

	// Instructions
	b.WriteString(DimStyle.Render("Scan this QR code with your authenticator app:"))
	b.WriteString("\n\n")

	// Render QR code
	qrCode, err := totp.RenderQRCodeForEntry(e.TOTPSecret, e.Title, e.Username)
	if err != nil {
		b.WriteString(ErrorStyle.Render("Failed to generate QR code: " + err.Error()))
	} else {
		// Center the QR code
		lines := strings.SplitSeq(qrCode, "\n")
		for line := range lines {
			b.WriteString(line)
			b.WriteString("\n")
		}
	}

	b.WriteString("\n")
	b.WriteString(DimStyle.Render("Compatible with Google Authenticator, Authy, and other TOTP apps"))
	b.WriteString("\n\n")

	// Bottom bar
	b.WriteString(RenderBottomBar([][]string{
		{"Close", "esc"},
	}, contentWidth))

	return centerContent(b.String(), width, height)
}
