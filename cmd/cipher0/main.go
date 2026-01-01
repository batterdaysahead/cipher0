// Package main is the entry point for the password manager.
package main

import (
	"bufio"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
	"golang.org/x/term"

	"github.com/batterdaysahead/cipher0/internal/config"
	"github.com/batterdaysahead/cipher0/internal/crypto"
	"github.com/batterdaysahead/cipher0/internal/ui"
	"github.com/batterdaysahead/cipher0/internal/vault"
)

// init disables core dumps to prevent sensitive data from being written to disk.
func init() {
	var rlim unix.Rlimit
	rlim.Cur = 0
	rlim.Max = 0
	_ = unix.Setrlimit(unix.RLIMIT_CORE, &rlim)
}

// vaultPath is the session-only vault path override from --vault flag.
var vaultPath string

func main() {
	// Catch panics and ensure memguard cleanup
	defer func() {
		if r := recover(); r != nil {
			crypto.SafeExit()
		}
	}()
	defer crypto.SafeExit()

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// rootCmd is the base command that runs the TUI by default.
var rootCmd = &cobra.Command{
	Use:     "cipher0",
	Short:   "Secure offline password manager",
	Version: config.AppVersion,
	Run:     runTUI,
}

func init() {
	// --vault flag for session-only vault path override
	rootCmd.Flags().StringVar(&vaultPath, "vault", "", "path to vault file (session only)")

	// Register subcommands
	rootCmd.AddCommand(backupCmd)
	rootCmd.AddCommand(restoreCmd)
	rootCmd.AddCommand(verifyCmd)
	rootCmd.AddCommand(configCmd)
}

// runTUI launches the terminal user interface.
func runTUI(cmd *cobra.Command, args []string) {
	if err := config.EnsureConfigDir(); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating config directory: %v\n", err)
		os.Exit(1)
	}

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	vPath := cfg.VaultPath
	if vaultPath != "" {
		vPath = vaultPath
	}

	app := ui.NewApp(vPath, cfg)
	p := tea.NewProgram(app, tea.WithAltScreen())

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	go func() {
		<-sigChan
		if v := app.GetVault(); v != nil {
			v.Lock()
		}
		crypto.SafeExit()
	}()

	defer func() {
		if v := app.GetVault(); v != nil {
			v.Lock()
		}
	}()

	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error running application: %v\n", err)
		os.Exit(1)
	}
}

// backupCmd creates an encrypted backup of the vault.
var backupCmd = &cobra.Command{
	Use:   "backup <path>",
	Short: "Create encrypted backup",
	Long:  "Create an encrypted backup of the vault. Requires master password to unlock.",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if err := config.EnsureConfigDir(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		cfg, _ := config.Load()
		vPath := cfg.VaultPath
		if vaultPath != "" {
			vPath = vaultPath
		}
		handleBackup(vPath, args[0])
	},
}

// restoreCmd restores vault from backup using recovery phrase.
var restoreCmd = &cobra.Command{
	Use:   "restore <path>",
	Short: "Restore from backup",
	Long:  "Restore vault from an encrypted backup. Requires 12-word recovery phrase.",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if err := config.EnsureConfigDir(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		cfg, _ := config.Load()
		vPath := cfg.VaultPath
		if vaultPath != "" {
			vPath = vaultPath
		}
		handleRestore(args[0], vPath)
	},
}

// verifyCmd verifies backup integrity without restoring.
var verifyCmd = &cobra.Command{
	Use:   "verify <path>",
	Short: "Verify backup integrity",
	Long:  "Verify a backup file is valid and can be decrypted with recovery phrase.",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		handleVerify(args[0])
	},
}

// configCmd manages application configuration.
var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage configuration",
	Long:  "View or modify application configuration settings.",
}

var configSetCmd = &cobra.Command{
	Use:   "set <key> <value>",
	Short: "Set a config value",
	Long:  "Set a configuration value. Available keys: vault",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		if err := config.EnsureConfigDir(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		cfg, err := config.Load()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
			os.Exit(1)
		}

		key, value := args[0], args[1]
		switch key {
		case "vault":
			cfg.VaultPath = value
		default:
			fmt.Fprintf(os.Stderr, "Unknown config key: %s\n", key)
			os.Exit(1)
		}

		if err := config.Save(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving config: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("%s = %s\n", key, value)
	},
}

var configGetCmd = &cobra.Command{
	Use:   "get <key>",
	Short: "Get a config value",
	Long:  "Get a configuration value. Available keys: vault",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if err := config.EnsureConfigDir(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		cfg, err := config.Load()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
			os.Exit(1)
		}

		switch args[0] {
		case "vault":
			fmt.Println(cfg.VaultPath)
		default:
			fmt.Fprintf(os.Stderr, "Unknown config key: %s\n", args[0])
			os.Exit(1)
		}
	},
}

func init() {
	configCmd.AddCommand(configSetCmd)
	configCmd.AddCommand(configGetCmd)
}

// readPassword securely reads a password from stdin without echoing.
func readPassword() (string, error) {
	fmt.Print("Enter password: ")
	password, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return "", err
	}
	return string(password), nil
}

// handleVerify verifies a backup file can be decrypted with the recovery phrase.
func handleVerify(path string) {
	fmt.Printf("Verifying backup: %s\n", path)
	fmt.Println("Enter your 12-word recovery phrase:")

	phrase := readPhrase()

	if err := vault.VerifyBackupWithPhrase(path, phrase); err != nil {
		fmt.Fprintf(os.Stderr, "Verification failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("✓ Backup is valid")
}

// handleRestore restores a vault from backup using the recovery phrase.
func handleRestore(backupPath, vaultPath string) {
	fmt.Printf("Restoring from: %s\n", backupPath)
	fmt.Printf("To vault: %s\n", vaultPath)

	// Warn if vault already exists
	if _, err := os.Stat(vaultPath); err == nil {
		fmt.Println("\n⚠️  WARNING: Vault already exists at this location!")
		fmt.Println("Restoring will REPLACE the existing vault.")
		fmt.Print("Type 'yes' to continue: ")
		reader := bufio.NewReader(os.Stdin)
		confirm, _ := reader.ReadString('\n')
		if strings.TrimSpace(confirm) != "yes" {
			fmt.Println("Restore cancelled.")
			os.Exit(0)
		}
	}

	fmt.Println("\nEnter your 12-word recovery phrase:")
	phrase := readPhrase()

	fmt.Println("\nSet a new master password for the restored vault:")
	newPassword := readNewPassword()

	v, err := vault.RestoreFromBackupWithPhrase(backupPath, vaultPath, phrase, newPassword)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Restore failed: %v\n", err)
		os.Exit(1)
	}
	v.Lock()

	fmt.Println("✓ Vault restored successfully with new password")
}

// readPhrase reads a recovery phrase from stdin (visible).
func readPhrase() string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("> ")
	phrase, err := reader.ReadString('\n')
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading phrase: %v\n", err)
		os.Exit(1)
	}
	return strings.TrimSpace(phrase)
}

// readNewPassword reads and confirms a new password with validation.
func readNewPassword() string {
	for {
		fmt.Print("New password: ")
		password1, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading password: %v\n", err)
			os.Exit(1)
		}

		fmt.Print("Confirm password: ")
		password2, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading password: %v\n", err)
			os.Exit(1)
		}

		if string(password1) != string(password2) {
			fmt.Println("Passwords do not match. Try again.")
			continue
		}

		if len(password1) < 8 {
			fmt.Println("Password must be at least 8 characters. Try again.")
			continue
		}

		return string(password1)
	}
}

// handleBackup creates an encrypted backup of the vault.
func handleBackup(vaultPath, backupPath string) {
	fmt.Printf("Creating backup from: %s\n", vaultPath)

	password, err := readPassword()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading password: %v\n", err)
		os.Exit(1)
	}

	v, err := vault.UnlockWithPassword(vaultPath, password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to unlock vault: %v\n", err)
		os.Exit(1)
	}
	defer v.Lock()

	if err := v.ExportEncryptedBackup(backupPath); err != nil {
		fmt.Fprintf(os.Stderr, "Backup failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓ Backup created: %s\n", backupPath)
}
