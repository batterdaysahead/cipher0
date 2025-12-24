// Package ui provides shared types and messages for the TUI.
package ui

import (
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/batterdaysahead/cipher0/internal/vault"
)

// Screen represents the current screen/view
type Screen int

const (
	ScreenLogin Screen = iota
	ScreenCreation
	ScreenRecoveryDisplay
	ScreenRecoveryInput
	ScreenMain
	ScreenEntry
	ScreenSettings
	ScreenBackup
)

// Message types for inter-component communication

// VaultCreatedMsg is sent when a new vault is created
type VaultCreatedMsg struct {
	Vault          *vault.Vault
	RecoveryPhrase string
}

// VaultUnlockedMsg is sent when the vault is unlocked
type VaultUnlockedMsg struct {
	Vault            *vault.Vault
	NeedsNewPassword bool // True for phrase-only vaults (backup files)
}

// VaultLockedMsg is sent when the vault is locked
type VaultLockedMsg struct{}

// UnlockFailedMsg is sent when unlock fails
type UnlockFailedMsg struct {
	Error string
}

// EntrySavedMsg is sent when an entry is saved
type EntrySavedMsg struct {
	Entry *vault.Entry
	IsNew bool
}

// EntryDeletedMsg is sent when an entry is deleted
type EntryDeletedMsg struct {
	EntryID string
}

// ClipboardCopiedMsg is sent when something is copied to clipboard
type ClipboardCopiedMsg struct {
	Content string
	Label   string // e.g., "Password", "Username", "TOTP"
}

// ClipboardErrorMsg is sent when clipboard operation fails
type ClipboardErrorMsg struct {
	Error string
}

// TOTPTickMsg is sent every second to update TOTP display
type TOTPTickMsg struct {
	Time time.Time
}

// AutoLockMsg is sent when auto-lock timer expires
type AutoLockMsg struct{}

// ScreenChangeMsg requests a screen change
type ScreenChangeMsg struct {
	Screen Screen
	Data   any // Optional data to pass to the new screen
}

// ErrorMsg is a general error message
type ErrorMsg struct {
	Error   string
	Details string
}

// SuccessMsg is a general success message
type SuccessMsg struct {
	Message string
}

// ConfirmationRequestMsg requests user confirmation
type ConfirmationRequestMsg struct {
	Title   string
	Message string
	OnYes   tea.Cmd
	OnNo    tea.Cmd
}

// ConfirmationResponseMsg is the response to a confirmation request
type ConfirmationResponseMsg struct {
	Confirmed bool
}

// PasswordGeneratedMsg is sent when a password is generated
type PasswordGeneratedMsg struct {
	Password string
}

// BackupCompletedMsg is sent when backup is complete
type BackupCompletedMsg struct {
	Path string
}

// BackupFailedMsg is sent when backup fails
type BackupFailedMsg struct {
	Error string
}

// Commands (tea.Cmd generators)

// NavigateTo creates a command to navigate to a screen
func NavigateTo(screen Screen, data any) tea.Cmd {
	return func() tea.Msg {
		return ScreenChangeMsg{Screen: screen, Data: data}
	}
}

// RequestConfirmation creates a confirmation request
func RequestConfirmation(title, message string, onYes, onNo tea.Cmd) tea.Cmd {
	return func() tea.Msg {
		return ConfirmationRequestMsg{
			Title:   title,
			Message: message,
			OnYes:   onYes,
			OnNo:    onNo,
		}
	}
}

// ClearNotificationMsg is sent to clear notification messages
type ClearNotificationMsg struct{}

// ClearNotificationAfter creates a command that clears notification after duration
func ClearNotificationAfter(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(t time.Time) tea.Msg {
		return ClearNotificationMsg{}
	})
}

// TOTPTick creates a command for TOTP timer ticks
func TOTPTick() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return TOTPTickMsg{Time: t}
	})
}
