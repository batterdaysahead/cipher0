package vault

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/batterdaysahead/cipher0/internal/crypto"
)

// mockKeyring holds the mock keyring instance for tests.
var mockKeyring *crypto.MockKeyring

// TestMain sets up a mock keyring for all tests in this package.
func TestMain(m *testing.M) {
	// Use mock keyring for all tests
	var cleanup func()
	mockKeyring, cleanup = crypto.UseMockKeyring()
	defer cleanup()

	os.Exit(m.Run())
}

// resetMockKeyring clears the mock keyring state between tests.
func resetMockKeyring() {
	if mockKeyring != nil {
		mockKeyring.Reset()
	}
}

func TestCreateAndUnlockVault(t *testing.T) {
	resetMockKeyring()
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "test.vault")
	password := "test-password-123"

	// Create vault
	vault, phrase, err := Create(vaultPath, password)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	defer vault.Lock()

	// Verify phrase is not empty
	if phrase == "" {
		t.Error("Recovery phrase should not be empty")
	}

	// Verify vault file exists
	if !DatabaseExists(vaultPath) {
		t.Error("Vault file should exist")
	}

	// Lock the vault
	vault.Lock()

	// Unlock with password
	vault2, err := UnlockWithPassword(vaultPath, password)
	if err != nil {
		t.Fatalf("UnlockWithPassword failed: %v", err)
	}
	defer vault2.Lock()

	if vault2.IsLocked() {
		t.Error("Vault should be unlocked")
	}
}

func TestUnlockWithPhrase(t *testing.T) {
	resetMockKeyring()
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "test.vault")
	password := "test-password-123"

	// Create vault
	vault, phrase, err := Create(vaultPath, password)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	vault.Lock()

	// Unlock with recovery phrase
	vault2, err := UnlockWithPhrase(vaultPath, phrase)
	if err != nil {
		t.Fatalf("UnlockWithPhrase failed: %v", err)
	}
	defer vault2.Lock()

	if vault2.IsLocked() {
		t.Error("Vault should be unlocked with phrase")
	}
}

func TestWrongPassword(t *testing.T) {
	resetMockKeyring()
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "test.vault")
	password := "correct-password"

	vault, _, err := Create(vaultPath, password)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	vault.Lock()

	_, err = UnlockWithPassword(vaultPath, "wrong-password")
	if err != ErrWrongPassword {
		t.Errorf("Expected ErrWrongPassword, got: %v", err)
	}
}

func TestEntryOperations(t *testing.T) {
	resetMockKeyring()
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "test.vault")

	vault, _, err := Create(vaultPath, "password")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	defer vault.Lock()

	// Add entry
	entry := NewEntry("GitHub")
	entry.Username = "user@example.com"
	entry.Password = "secret123"
	entry.URL = "https://github.com"

	if err := vault.AddEntry(entry); err != nil {
		t.Fatalf("AddEntry failed: %v", err)
	}

	// Verify entry count
	if count := vault.EntryCount(); count != 1 {
		t.Errorf("Expected 1 entry, got %d", count)
	}

	// Get entry
	retrieved, err := vault.GetEntry(entry.ID)
	if err != nil {
		t.Fatalf("GetEntry failed: %v", err)
	}

	if retrieved.Title != "GitHub" {
		t.Errorf("Expected title 'GitHub', got '%s'", retrieved.Title)
	}

	// Update entry
	retrieved.Title = "GitHub Updated"
	if err := vault.UpdateEntry(retrieved); err != nil {
		t.Fatalf("UpdateEntry failed: %v", err)
	}

	// Verify update
	updated, _ := vault.GetEntry(entry.ID)
	if updated.Title != "GitHub Updated" {
		t.Errorf("Expected updated title, got '%s'", updated.Title)
	}

	// Delete entry
	if err := vault.DeleteEntry(entry.ID); err != nil {
		t.Fatalf("DeleteEntry failed: %v", err)
	}

	if count := vault.EntryCount(); count != 0 {
		t.Errorf("Expected 0 entries after delete, got %d", count)
	}
}

func TestSaveAndReload(t *testing.T) {
	resetMockKeyring()
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "test.vault")
	password := "password"

	vault, _, err := Create(vaultPath, password)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Add entries
	entry1 := NewEntry("Entry 1")
	entry1.Password = "pass1"
	vault.AddEntry(entry1)

	entry2 := NewEntry("Entry 2")
	entry2.Password = "pass2"
	entry2.TOTPSecret = "JBSWY3DPEHPK3PXP"
	vault.AddEntry(entry2)

	// Save
	if err := vault.Save(); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	vault.Lock()

	// Reload
	vault2, err := UnlockWithPassword(vaultPath, password)
	if err != nil {
		t.Fatalf("Reload failed: %v", err)
	}
	defer vault2.Lock()

	// Verify entries
	if count := vault2.EntryCount(); count != 2 {
		t.Errorf("Expected 2 entries, got %d", count)
	}

	retrieved, _ := vault2.GetEntry(entry2.ID)
	if retrieved.TOTPSecret != "JBSWY3DPEHPK3PXP" {
		t.Error("TOTP secret not preserved")
	}
}

func TestChangePassword(t *testing.T) {
	resetMockKeyring()
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "test.vault")
	oldPassword := "old-password"
	newPassword := "new-password"

	vault, phrase, err := Create(vaultPath, oldPassword)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Add an entry
	entry := NewEntry("Test")
	entry.Password = "secret"
	vault.AddEntry(entry)
	vault.Save()

	// Change password
	if err := vault.ChangePassword(oldPassword, newPassword); err != nil {
		t.Fatalf("ChangePassword failed: %v", err)
	}

	vault.Lock()

	// Old password should not work
	_, err = UnlockWithPassword(vaultPath, oldPassword)
	if err != ErrWrongPassword {
		t.Error("Old password should not work")
	}

	// New password should work
	vault2, err := UnlockWithPassword(vaultPath, newPassword)
	if err != nil {
		t.Fatalf("New password should work: %v", err)
	}
	defer vault2.Lock()

	// Verify data is intact
	if count := vault2.EntryCount(); count != 1 {
		t.Error("Entry should still exist")
	}

	// Recovery phrase should still work
	vault2.Lock()
	vault3, err := UnlockWithPhrase(vaultPath, phrase)
	if err != nil {
		t.Fatalf("Recovery phrase should still work: %v", err)
	}
	vault3.Lock()
}

func TestSearch(t *testing.T) {
	resetMockKeyring()
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "test.vault")

	vault, _, _ := Create(vaultPath, "password")
	defer vault.Lock()

	// Add entries
	e1 := NewEntry("GitHub")
	e1.Username = "user@github.com"
	vault.AddEntry(e1)

	e2 := NewEntry("Gmail")
	e2.Username = "user@gmail.com"
	vault.AddEntry(e2)

	e3 := NewEntry("AWS Console")
	e3.Username = "admin"
	vault.AddEntry(e3)

	// Search by title
	results := vault.Search("git")
	if len(results) != 1 {
		t.Errorf("Expected 1 result for 'git', got %d", len(results))
	}

	// Search by username
	results = vault.Search("user@")
	if len(results) != 2 {
		t.Errorf("Expected 2 results for 'user@', got %d", len(results))
	}
}

func TestVaultNotFound(t *testing.T) {
	_, err := UnlockWithPassword("/nonexistent/path.vault", "password")
	if err != ErrVaultNotFound {
		t.Errorf("Expected ErrVaultNotFound, got: %v", err)
	}
}

func TestBackup(t *testing.T) {
	resetMockKeyring()
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "test.vault")
	backupPath := filepath.Join(tmpDir, "backup.vault")
	password := "password"

	// Create vault with entries
	vault, phrase, _ := Create(vaultPath, password)
	entry := NewEntry("Test Entry")
	entry.Password = "secret"
	vault.AddEntry(entry)
	vault.Save()

	// Create backup
	if err := vault.ExportEncryptedBackup(backupPath); err != nil {
		t.Fatalf("ExportEncryptedBackup failed: %v", err)
	}

	// Verify backup file exists
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		t.Error("Backup file should exist")
	}

	// Verify backup with phrase (not password)
	if err := VerifyBackupWithPhrase(backupPath, phrase); err != nil {
		t.Fatalf("VerifyBackupWithPhrase failed: %v", err)
	}

	vault.Lock()
}

func TestPlaintextExport(t *testing.T) {
	resetMockKeyring()
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "test.vault")
	exportPath := filepath.Join(tmpDir, "export.json")

	vault, _, _ := Create(vaultPath, "password")
	entry := NewEntry("Test")
	entry.Password = "secret123"
	vault.AddEntry(entry)

	// Export plaintext
	if err := vault.ExportPlaintext(exportPath); err != nil {
		t.Fatalf("ExportPlaintext failed: %v", err)
	}

	// Read and verify
	data, err := os.ReadFile(exportPath)
	if err != nil {
		t.Fatalf("Failed to read export: %v", err)
	}

	// Should contain the password in plaintext
	if !contains(string(data), "secret123") {
		t.Error("Export should contain plaintext password")
	}

	vault.Lock()
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && contains(s[1:], substr) || s[:len(substr)] == substr)
}
