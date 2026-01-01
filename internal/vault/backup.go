// Package vault provides vault management for the password manager.
package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/batterdaysahead/cipher0/internal/crypto"
)

var (
	// ErrBackupFailed is returned when backup creation fails.
	ErrBackupFailed = errors.New("backup creation failed")
	// ErrRestoreFailed is returned when restore operation fails.
	ErrRestoreFailed = errors.New("backup restore failed")
	// ErrBackupInvalid is returned when backup verification fails.
	ErrBackupInvalid = errors.New("backup is invalid or corrupted")
)

// PlaintextExport represents an unencrypted export of the vault.
type PlaintextExport struct {
	Version    string    `json:"version"`
	ExportedAt time.Time `json:"exported_at"`
	Entries    EntryList `json:"entries"`
}

// ExportEncryptedBackup creates an encrypted backup of the vault.
// SECURITY: The backup file has password-encrypted MEK removed, so it can
// ONLY be restored with the 12-word recovery phrase.
func (v *Vault) ExportEncryptedBackup(backupPath string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	// Ensure any pending changes are saved
	if v.modified {
		if err := v.saveLocked(); err != nil {
			return fmt.Errorf("failed to save vault before backup: %w", err)
		}
	}

	// Ensure backup directory exists
	dir := filepath.Dir(backupPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create backup directory: %w", err)
	}

	// Create a copy of the database without password-encrypted MEK
	// This ensures backups can ONLY be restored with the recovery phrase
	backupDB := &Database{
		Version:              v.db.Version,
		SecurityMode:         v.db.SecurityMode,
		KDF:                  v.db.KDF,
		SaltPassword:         "", // Clear - no password unlock for backups
		SaltPhrase:           v.db.SaltPhrase,
		EncryptedMEKPassword: "", // Clear - no password unlock for backups
		EncryptedMEKPhrase:   v.db.EncryptedMEKPhrase,
		EncryptedData:        "", // Will be set below with new AAD
		LastBackup:           v.db.LastBackup,
	}

	// Re-encrypt with backup's AAD (headers changed)
	dataJSON, err := json.Marshal(v.data)
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}
	defer crypto.ZeroMemory(dataJSON)

	aad := backupDB.BuildAAD()
	mekBytes, mekCleanup, err := v.mek.Bytes()
	if err != nil {
		return err
	}
	defer mekCleanup()
	encData, err := crypto.EncryptWithAAD(dataJSON, mekBytes, aad)
	if err != nil {
		return fmt.Errorf("failed to encrypt data: %w", err)
	}
	backupDB.SetEncryptedData(encData)

	// Save backup database
	if err := SaveDatabase(backupDB, backupPath); err != nil {
		return fmt.Errorf("%w: %v", ErrBackupFailed, err)
	}

	// Update last backup timestamp in the main vault
	now := time.Now()
	v.db.SetLastBackup(now)

	// Save updated timestamp
	if err := v.saveLocked(); err != nil {
		return fmt.Errorf("failed to update backup timestamp: %w", err)
	}

	return nil
}

// ExportPlaintext exports the vault as unencrypted JSON.
// WARNING: This creates an unencrypted file. Use with extreme caution.
func (v *Vault) ExportPlaintext(path string) error {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.data == nil {
		return ErrVaultLocked
	}

	export := PlaintextExport{
		Version:    DatabaseVersion,
		ExportedAt: time.Now(),
		Entries:    v.data.Entries,
	}

	data, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal export: %w", err)
	}

	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create export directory: %w", err)
	}

	// Write with secure permissions
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write export: %w", err)
	}

	return nil
}

// RestoreFromBackupWithPhrase restores using recovery phrase and sets a new master password.
// The new password is required because backup restore should force a password reset.
func RestoreFromBackupWithPhrase(backupPath, vaultPath, phrase, newPassword string) (*Vault, error) {
	// First verify the backup is valid and get the MEK
	testVault, err := UnlockWithPhrase(backupPath, phrase)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBackupInvalid, err)
	}
	testVault.Lock()

	// Ensure vault directory exists
	dir := filepath.Dir(vaultPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create vault directory: %w", err)
	}

	// Copy backup to vault location
	if err := copyFile(backupPath, vaultPath); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRestoreFailed, err)
	}

	// Open the restored vault with phrase
	v, err := UnlockWithPhrase(vaultPath, phrase)
	if err != nil {
		return nil, fmt.Errorf("failed to open restored vault: %w", err)
	}

	// Set the new password (re-encrypt MEK with new password)
	if err := v.SetNewPassword(newPassword); err != nil {
		v.Lock()
		return nil, fmt.Errorf("failed to set new password: %w", err)
	}

	return v, nil
}

// VerifyBackupWithPhrase verifies a backup using recovery phrase.
func VerifyBackupWithPhrase(backupPath, phrase string) error {
	vault, err := UnlockWithPhrase(backupPath, phrase)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBackupInvalid, err)
	}
	vault.Lock()
	return nil
}

// copyFile copies a file from src to dst.
func copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return err
	}

	return dstFile.Sync()
}

// GenerateBackupFilename generates a backup filename with timestamp.
func GenerateBackupFilename(baseName string) string {
	timestamp := time.Now().Format("2006-01-02_150405")
	return fmt.Sprintf("%s_backup_%s.c0", baseName, timestamp)
}
