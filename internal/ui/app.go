// Package ui provides the TUI interface for the password manager.
package ui

import (
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/batterdaysahead/cipher0/internal/config"
	"github.com/batterdaysahead/cipher0/internal/utils"
	"github.com/batterdaysahead/cipher0/internal/vault"
)

const notificationTimeout = 3 * time.Second

// App is the main application model
type App struct {
	// Core state
	vault      *vault.Vault
	config     *config.Config
	vaultPath  string
	screen     Screen
	prevScreen Screen
	screenData any

	// Components
	clipboard    *utils.ClipboardManager
	autoLock     *utils.AutoLockTimer
	autoLockChan chan struct{}

	// Window size
	width  int
	height int

	// UI state
	error          string
	success        string
	recoveryPhrase string // Temporary storage during creation

	// Screen models
	loginModel           *LoginModel
	creationModel        *CreationModel
	recoveryDisplayModel *RecoveryDisplayModel
	recoveryInputModel   *RecoveryInputModel
	mainModel            *MainModel
	entryModel           *EntryModel
	settingsModel        *SettingsModel
	backupModel          *BackupModel

	// Dialog state
	showConfirmation bool
	confirmationMsg  ConfirmationRequestMsg
}

// NewApp creates a new application instance
func NewApp(vaultPath string, cfg *config.Config) *App {
	if cfg == nil {
		cfg, _ = config.Load()
	}
	if vaultPath == "" {
		vaultPath = cfg.VaultPath
	}

	app := &App{
		config:       cfg,
		vaultPath:    vaultPath,
		screen:       ScreenLogin,
		clipboard:    utils.NewClipboardManager(time.Duration(cfg.ClipboardTimeout) * time.Second),
		autoLockChan: make(chan struct{}, 1),
		width:        80,
		height:       24,
	}

	// Initialize screen models
	app.loginModel = NewLoginModelWithVault(vaultPath)
	app.creationModel = NewCreationModel()

	return app
}

// Init implements tea.Model
func (a *App) Init() tea.Cmd {
	// Check if vault exists
	if !vault.DatabaseExists(a.vaultPath) {
		a.screen = ScreenCreation
		return a.creationModel.Init()
	}

	// Check if vault is phrase-only (backup file copied as vault)
	if vault.IsPhraseOnlyVault(a.vaultPath) {
		a.screen = ScreenRecoveryInput
		a.recoveryInputModel = NewRecoveryInputModel()
		a.recoveryInputModel.isPhraseOnlyVault = true // Mark as phrase-only for special handling
		return a.recoveryInputModel.Init()
	}

	return a.loginModel.Init()
}

// Update implements tea.Model
func (a *App) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	// Handle global messages
	switch msg := msg.(type) {
	case tea.KeyMsg:
		// Reset auto-lock timer on any keypress
		if a.autoLock != nil {
			a.autoLock.Reset()
		}

		// Global quit
		if msg.Type == tea.KeyCtrlC {
			return a, tea.Quit
		}

		// Clear messages on any key
		a.error = ""
		a.success = ""

	case tea.WindowSizeMsg:
		a.width = msg.Width
		a.height = msg.Height

	case VaultCreatedMsg:
		a.vault = msg.Vault
		a.recoveryPhrase = msg.RecoveryPhrase
		a.screen = ScreenRecoveryDisplay
		a.recoveryDisplayModel = NewRecoveryDisplayModel(msg.RecoveryPhrase)
		return a, a.recoveryDisplayModel.Init()

	case VaultUnlockedMsg:
		a.vault = msg.Vault
		a.startAutoLock()

		// For phrase-only vaults (backup files), require new password setup
		if msg.NeedsNewPassword {
			a.screen = ScreenSettings
			a.settingsModel = NewSettingsModel(a.config, a.vault)
			a.settingsModel.requirePasswordSetup = true // Signal to settings
			a.success = "Vault unlocked. Please set a new master password."
			return a, a.settingsModel.Init()
		}

		a.screen = ScreenMain
		a.mainModel = NewMainModel(a.vault, a.clipboard)
		return a, tea.Batch(a.mainModel.Init(), TOTPTick(), a.waitForAutoLock())

	case VaultLockedMsg:
		a.lockVault()
		return a, nil

	case UnlockFailedMsg:
		a.error = msg.Error
		return a, nil

	case AutoLockMsg:
		if a.vault != nil {
			a.lockVault()
			a.success = "Vault auto-locked due to inactivity"
		}
		return a, nil

	case ScreenChangeMsg:
		return a.handleScreenChange(msg)

	case ClearNotificationMsg:
		a.error = ""
		a.success = ""
		// Don't return here - let it propagate to screen models

	case ErrorMsg:
		a.error = msg.Error
		return a, ClearNotificationAfter(notificationTimeout)

	case SuccessMsg:
		a.success = msg.Message
		return a, ClearNotificationAfter(notificationTimeout)

	case ClipboardCopiedMsg:
		a.success = msg.Label + " copied to clipboard"
		return a, nil // Clear on next keypress, not by timer

	case ClipboardErrorMsg:
		a.error = "Clipboard: " + msg.Error
		return a, ClearNotificationAfter(notificationTimeout)

	case ConfirmationRequestMsg:
		a.showConfirmation = true
		a.confirmationMsg = msg
		return a, nil

	case ConfirmationResponseMsg:
		a.showConfirmation = false
		if msg.Confirmed && a.confirmationMsg.OnYes != nil {
			return a, a.confirmationMsg.OnYes
		} else if !msg.Confirmed && a.confirmationMsg.OnNo != nil {
			return a, a.confirmationMsg.OnNo
		}
		return a, nil
	}

	// Handle confirmation dialog
	if a.showConfirmation {
		return a.handleConfirmation(msg)
	}

	// Delegate to current screen
	switch a.screen {
	case ScreenLogin:
		var cmd tea.Cmd
		a.loginModel, cmd = a.loginModel.Update(msg, a.vaultPath)
		cmds = append(cmds, cmd)

	case ScreenCreation:
		var cmd tea.Cmd
		a.creationModel, cmd = a.creationModel.Update(msg, a.vaultPath)
		cmds = append(cmds, cmd)

	case ScreenRecoveryDisplay:
		var cmd tea.Cmd
		a.recoveryDisplayModel, cmd = a.recoveryDisplayModel.Update(msg)
		cmds = append(cmds, cmd)

	case ScreenRecoveryInput:
		var cmd tea.Cmd
		a.recoveryInputModel, cmd = a.recoveryInputModel.Update(msg, a.vaultPath)
		cmds = append(cmds, cmd)

	case ScreenMain:
		var cmd tea.Cmd
		a.mainModel, cmd = a.mainModel.Update(msg)
		cmds = append(cmds, cmd)

	case ScreenEntry:
		var cmd tea.Cmd
		a.entryModel, cmd = a.entryModel.Update(msg)
		cmds = append(cmds, cmd)

	case ScreenSettings:
		var cmd tea.Cmd
		a.settingsModel, cmd = a.settingsModel.Update(msg)
		cmds = append(cmds, cmd)

	case ScreenBackup:
		var cmd tea.Cmd
		a.backupModel, cmd = a.backupModel.Update(msg)
		cmds = append(cmds, cmd)
	}

	return a, tea.Batch(cmds...)
}

// View implements tea.Model
func (a *App) View() string {
	if a.showConfirmation {
		return a.renderConfirmation()
	}

	var content string

	switch a.screen {
	case ScreenLogin:
		content = a.loginModel.View(a.width, a.height)
	case ScreenCreation:
		content = a.creationModel.View(a.width, a.height)
	case ScreenRecoveryDisplay:
		content = a.recoveryDisplayModel.View(a.width, a.height)
	case ScreenRecoveryInput:
		content = a.recoveryInputModel.View(a.width, a.height)
	case ScreenMain:
		// Pass success message to main model for display
		if a.success != "" {
			a.mainModel.message = a.success
			a.mainModel.messageType = "success"
			a.success = ""
		}
		if a.error != "" {
			a.mainModel.message = a.error
			a.mainModel.messageType = "error"
			a.error = ""
		}
		content = a.mainModel.View(a.width, a.height)
	case ScreenEntry:
		content = a.entryModel.View(a.width, a.height)
	case ScreenSettings:
		content = a.settingsModel.View(a.width, a.height)
	case ScreenBackup:
		content = a.backupModel.View(a.width, a.height)
	default:
		content = "Unknown screen"
	}

	return content
}

// handleScreenChange handles screen navigation
func (a *App) handleScreenChange(msg ScreenChangeMsg) (tea.Model, tea.Cmd) {
	a.prevScreen = a.screen
	a.screen = msg.Screen
	a.screenData = msg.Data
	a.error = ""
	a.success = ""

	var cmd tea.Cmd

	switch msg.Screen {
	case ScreenLogin:
		a.loginModel = NewLoginModelWithVault(a.vaultPath)
		cmd = a.loginModel.Init()

	case ScreenCreation:
		a.creationModel = NewCreationModel()
		cmd = a.creationModel.Init()

	case ScreenRecoveryInput:
		a.recoveryInputModel = NewRecoveryInputModel()
		cmd = a.recoveryInputModel.Init()

	case ScreenMain:
		if a.mainModel == nil && a.vault != nil {
			a.mainModel = NewMainModel(a.vault, a.clipboard)
		} else if a.mainModel != nil {
			// Refresh entries when navigating back from entry/settings screens
			a.mainModel.refreshEntries()
		}
		cmd = tea.Batch(a.mainModel.Init(), TOTPTick())

	case ScreenEntry:
		entry, _ := msg.Data.(*vault.Entry)
		a.entryModel = NewEntryModel(a.vault, entry, a.clipboard)
		cmd = a.entryModel.Init()

	case ScreenSettings:
		a.settingsModel = NewSettingsModel(a.config, a.vault)
		cmd = a.settingsModel.Init()

	case ScreenBackup:
		a.backupModel = NewBackupModel(a.vault)
		cmd = a.backupModel.Init()
	}

	return a, cmd
}

// handleConfirmation handles confirmation dialog input
func (a *App) handleConfirmation(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "y", "Y":
			return a, func() tea.Msg {
				return ConfirmationResponseMsg{Confirmed: true}
			}
		case "n", "N", "esc":
			return a, func() tea.Msg {
				return ConfirmationResponseMsg{Confirmed: false}
			}
		}
	}
	return a, nil
}

// renderConfirmation renders the confirmation dialog
func (a *App) renderConfirmation() string {
	var content strings.Builder

	content.WriteString(WarningStyle.Render(a.confirmationMsg.Title))
	content.WriteString("\n")
	content.WriteString(SubtitleStyle.Render(a.confirmationMsg.Message))
	content.WriteString("\n\n")

	// Bottom bar matching main screen style
	content.WriteString(RenderBottomBar([][]string{
		{"Confirm", "y"},
		{"Cancel", "n/esc"},
	}, 40))

	return centerContent(content.String(), a.width, a.height)
}

// lockVault locks the vault and returns to login
func (a *App) lockVault() {
	if a.vault != nil {
		a.vault.Lock()
		a.vault = nil
	}
	if a.autoLock != nil {
		a.autoLock.Stop()
	}
	a.screen = ScreenLogin
	a.loginModel = NewLoginModelWithVault(a.vaultPath)
	a.mainModel = nil
	a.entryModel = nil
	a.settingsModel = nil
	a.backupModel = nil
	a.recoveryPhrase = ""
}

// startAutoLock starts the auto-lock timer
func (a *App) startAutoLock() {
	if a.config.AutoLockTimeout > 0 {
		a.autoLock = utils.NewAutoLockTimer(
			time.Duration(a.config.AutoLockTimeout)*time.Second,
			func() {
				// Send signal to channel when timer expires
				select {
				case a.autoLockChan <- struct{}{}:
				default:
				}
			},
		)
		a.autoLock.Start()
	}
}

// waitForAutoLock returns a command that waits for auto-lock signal
func (a *App) waitForAutoLock() tea.Cmd {
	return func() tea.Msg {
		<-a.autoLockChan
		return AutoLockMsg{}
	}
}

// GetVault returns the current vault
func (a *App) GetVault() *vault.Vault {
	return a.vault
}
