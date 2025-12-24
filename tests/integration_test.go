// Package tests contains integration tests for the password manager.
package tests

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/batterdaysahead/cipher0/internal/crypto"
	"github.com/batterdaysahead/cipher0/internal/totp"
	"github.com/batterdaysahead/cipher0/internal/utils"
	"github.com/batterdaysahead/cipher0/internal/vault"
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

// TestFullVaultLifecycle tests the complete vault lifecycle:
// create -> add entries -> save -> lock -> unlock -> verify data
func TestFullVaultLifecycle(t *testing.T) {
	resetMockKeyring()
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "test.vault")
	password := "secure-test-password-123!"

	// 1. Create new vault
	t.Log("Creating new vault...")
	v, phrase, err := vault.Create(vaultPath, password)
	if err != nil {
		t.Fatalf("Failed to create vault: %v", err)
	}
	if len(strings.Fields(phrase)) != 12 {
		t.Fatalf("Expected 12-word recovery phrase, got %d words", len(strings.Fields(phrase)))
	}
	t.Logf("Vault created with recovery phrase: %s...", phrase[:20])

	// 2. Add multiple entries
	t.Log("Adding entries...")
	entries := []struct {
		title    string
		username string
		password string
		url      string
	}{
		{"GitHub", "user@github.com", "gh-password-123", "https://github.com"},
		{"Gmail", "user@gmail.com", "gmail-password-456", "https://gmail.com"},
		{"Twitter", "twitteruser", "twitter-pass-789", "https://twitter.com"},
	}

	for _, e := range entries {
		entry := vault.NewEntry(e.title)
		entry.Username = e.username
		entry.Password = e.password
		entry.URL = e.url
		if err := v.AddEntry(entry); err != nil {
			t.Fatalf("Failed to add entry %s: %v", e.title, err)
		}
	}

	// 3. Verify entry count
	if count := v.EntryCount(); count != 3 {
		t.Fatalf("Expected 3 entries, got %d", count)
	}

	// 4. Save vault
	t.Log("Saving vault...")
	if err := v.Save(); err != nil {
		t.Fatalf("Failed to save vault: %v", err)
	}

	// 5. Lock vault
	t.Log("Locking vault...")
	v.Lock()

	// 6. Verify vault file exists
	if _, err := os.Stat(vaultPath); os.IsNotExist(err) {
		t.Fatal("Vault file does not exist after save")
	}

	// 7. Unlock with password
	t.Log("Unlocking with password...")
	v2, err := vault.UnlockWithPassword(vaultPath, password)
	if err != nil {
		t.Fatalf("Failed to unlock vault: %v", err)
	}

	// 8. Verify data integrity
	t.Log("Verifying data integrity...")
	if count := v2.EntryCount(); count != 3 {
		t.Fatalf("Expected 3 entries after unlock, got %d", count)
	}

	allEntries := v2.Entries()
	for _, entry := range allEntries {
		found := false
		for _, e := range entries {
			if entry.Title == e.title {
				found = true
				if entry.Username != e.username {
					t.Errorf("Entry %s: username mismatch", e.title)
				}
				if entry.Password != e.password {
					t.Errorf("Entry %s: password mismatch", e.title)
				}
				break
			}
		}
		if !found {
			t.Errorf("Unknown entry found: %s", entry.Title)
		}
	}

	v2.Lock()

	// 9. Unlock with recovery phrase
	t.Log("Unlocking with recovery phrase...")
	v3, err := vault.UnlockWithPhrase(vaultPath, phrase)
	if err != nil {
		t.Fatalf("Failed to unlock with recovery phrase: %v", err)
	}
	if count := v3.EntryCount(); count != 3 {
		t.Fatalf("Expected 3 entries after phrase unlock, got %d", count)
	}
	v3.Lock()

	t.Log("✓ Full vault lifecycle test passed")
}

// TestPasswordChange tests changing the master password
func TestPasswordChange(t *testing.T) {
	resetMockKeyring()
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "test.vault")
	oldPassword := "old-password-123"
	newPassword := "new-password-456"

	// Create vault
	v, phrase, err := vault.Create(vaultPath, oldPassword)
	if err != nil {
		t.Fatalf("Failed to create vault: %v", err)
	}

	// Add an entry
	entry := vault.NewEntry("Test Entry")
	entry.Password = "secret-data"
	v.AddEntry(entry)
	v.Save()

	// Change password
	t.Log("Changing password...")
	if err := v.ChangePassword(oldPassword, newPassword); err != nil {
		t.Fatalf("Failed to change password: %v", err)
	}
	v.Lock()

	// Old password should fail
	t.Log("Verifying old password fails...")
	_, err = vault.UnlockWithPassword(vaultPath, oldPassword)
	if err == nil {
		t.Fatal("Old password should not work after change")
	}

	// New password should work
	t.Log("Verifying new password works...")
	v2, err := vault.UnlockWithPassword(vaultPath, newPassword)
	if err != nil {
		t.Fatalf("New password should work: %v", err)
	}

	// Verify data is intact
	if count := v2.EntryCount(); count != 1 {
		t.Fatalf("Expected 1 entry, got %d", count)
	}
	v2.Lock()

	// Recovery phrase should still work
	t.Log("Verifying recovery phrase still works...")
	v3, err := vault.UnlockWithPhrase(vaultPath, phrase)
	if err != nil {
		t.Fatalf("Recovery phrase should still work: %v", err)
	}
	v3.Lock()

	t.Log("✓ Password change test passed")
}

// TestBackupAndRestore tests backup creation and restoration
func TestBackupAndRestore(t *testing.T) {
	resetMockKeyring()
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "test.vault")
	backupPath := filepath.Join(tmpDir, "backup.vault")
	restoredPath := filepath.Join(tmpDir, "restored.vault")
	password := "test-password"
	newPassword := "new-restored-password"

	// Create vault with entries
	v, phrase, err := vault.Create(vaultPath, password)
	if err != nil {
		t.Fatalf("Failed to create vault: %v", err)
	}

	entry := vault.NewEntry("Important Account")
	entry.Username = "admin"
	entry.Password = "super-secret"
	v.AddEntry(entry)
	v.Save()

	// Create backup
	t.Log("Creating backup...")
	if err := v.ExportEncryptedBackup(backupPath); err != nil {
		t.Fatalf("Failed to create backup: %v", err)
	}
	v.Lock()

	// Verify backup exists
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		t.Fatal("Backup file does not exist")
	}

	// Verify backup with phrase (not password)
	t.Log("Verifying backup with phrase...")
	if err := vault.VerifyBackupWithPhrase(backupPath, phrase); err != nil {
		t.Fatalf("Backup verification failed: %v", err)
	}

	// Restore backup with phrase and new password
	t.Log("Restoring from backup with phrase...")
	v2, err := vault.RestoreFromBackupWithPhrase(backupPath, restoredPath, phrase, newPassword)
	if err != nil {
		t.Fatalf("Failed to restore backup: %v", err)
	}

	// Verify restored data
	if count := v2.EntryCount(); count != 1 {
		t.Fatalf("Expected 1 entry in restored vault, got %d", count)
	}

	entries := v2.Entries()
	if entries[0].Title != "Important Account" {
		t.Errorf("Restored entry title mismatch")
	}
	if entries[0].Username != "admin" {
		t.Errorf("Restored entry username mismatch")
	}
	v2.Lock()

	// Verify new password works
	t.Log("Verifying new password works...")
	v3, err := vault.UnlockWithPassword(restoredPath, newPassword)
	if err != nil {
		t.Fatalf("New password should work: %v", err)
	}
	v3.Lock()

	// Verify old password no longer works
	t.Log("Verifying old password fails...")
	_, err = vault.UnlockWithPassword(restoredPath, password)
	if err == nil {
		t.Fatal("Old password should not work after restore with new password")
	}

	t.Log("✓ Backup and restore test passed")
}

// TestEntryOperations tests CRUD operations on entries
func TestEntryOperations(t *testing.T) {
	resetMockKeyring()
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "test.vault")
	password := "test-password"

	v, _, err := vault.Create(vaultPath, password)
	if err != nil {
		t.Fatalf("Failed to create vault: %v", err)
	}

	// Create
	t.Log("Testing Create...")
	entry := vault.NewEntry("Test Entry")
	entry.Username = "testuser"
	entry.Password = "testpass"
	entry.URL = "https://test.com"
	entry.Notes = "Test notes"

	if err := v.AddEntry(entry); err != nil {
		t.Fatalf("Failed to add entry: %v", err)
	}

	// Read
	t.Log("Testing Read...")
	found, err := v.GetEntry(entry.ID)
	if err != nil {
		t.Fatal("Failed to retrieve entry")
	}
	if found.Title != entry.Title {
		t.Errorf("Title mismatch: got %s, want %s", found.Title, entry.Title)
	}

	// Update
	t.Log("Testing Update...")
	entry.Title = "Updated Title"
	entry.Password = "new-password"
	if err := v.UpdateEntry(entry); err != nil {
		t.Fatalf("Failed to update entry: %v", err)
	}

	updated, err := v.GetEntry(entry.ID)
	if err != nil {
		t.Fatal("Failed to get updated entry")
	}
	if updated.Title != "Updated Title" {
		t.Errorf("Update failed: title not changed")
	}
	if updated.Password != "new-password" {
		t.Errorf("Update failed: password not changed")
	}

	// Delete
	t.Log("Testing Delete...")
	if err := v.DeleteEntry(entry.ID); err != nil {
		t.Fatalf("Failed to delete entry: %v", err)
	}
	if v.EntryCount() != 0 {
		t.Errorf("Expected 0 entries after delete, got %d", v.EntryCount())
	}

	v.Lock()
	t.Log("✓ Entry operations test passed")
}

// TestTOTPIntegration tests TOTP functionality with entries
func TestTOTPIntegration(t *testing.T) {
	resetMockKeyring()
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "test.vault")
	password := "test-password"

	v, _, err := vault.Create(vaultPath, password)
	if err != nil {
		t.Fatalf("Failed to create vault: %v", err)
	}

	// Valid TOTP secret (base32 encoded)
	totpSecret := "JBSWY3DPEHPK3PXP"

	entry := vault.NewEntry("2FA Account")
	entry.Username = "user@example.com"
	entry.Password = "password123"
	entry.TOTPSecret = totpSecret
	v.AddEntry(entry)
	v.Save()
	v.Lock()

	// Unlock and verify TOTP generation
	v2, err := vault.UnlockWithPassword(vaultPath, password)
	if err != nil {
		t.Fatalf("Failed to unlock: %v", err)
	}

	entries := v2.Entries()
	if len(entries) != 1 {
		t.Fatalf("Expected 1 entry, got %d", len(entries))
	}

	secret := entries[0].TOTPSecret
	if !totp.ValidateSecret(secret) {
		t.Fatal("TOTP secret should be valid")
	}

	code, remaining, err := totp.GenerateCode(secret)
	if err != nil {
		t.Fatalf("Failed to generate TOTP code: %v", err)
	}

	if len(code) != 6 {
		t.Errorf("Expected 6-digit TOTP code, got %d digits", len(code))
	}
	if remaining < 0 || remaining > 30 {
		t.Errorf("Invalid remaining time: %d", remaining)
	}

	t.Logf("TOTP code: %s (expires in %ds)", totp.FormatCode(code), remaining)

	v2.Lock()
	t.Log("✓ TOTP integration test passed")
}

// TestPasswordGenerator tests password generation
func TestPasswordGenerator(t *testing.T) {
	opts := utils.DefaultGeneratorOptions()

	// Generate multiple passwords and verify they're unique
	passwords := make(map[string]bool)
	for i := 0; i < 10; i++ {
		pwd, err := utils.GeneratePassword(opts)
		if err != nil {
			t.Fatalf("Failed to generate password: %v", err)
		}
		if len(pwd) != opts.Length {
			t.Errorf("Password length mismatch: got %d, want %d", len(pwd), opts.Length)
		}
		if passwords[pwd] {
			t.Error("Generated duplicate password")
		}
		passwords[pwd] = true
	}

	// Test custom options
	customOpts := utils.GeneratorOptions{
		Length:           32,
		IncludeUppercase: true,
		IncludeLowercase: true,
		IncludeDigits:    true,
		IncludeSymbols:   true,
		ExcludeAmbiguous: true,
	}
	pwd, err := utils.GeneratePassword(customOpts)
	if err != nil {
		t.Fatalf("Failed to generate custom password: %v", err)
	}
	if len(pwd) != 32 {
		t.Errorf("Custom password length mismatch: got %d, want 32", len(pwd))
	}

	t.Log("✓ Password generator test passed")
}

// TestClipboardManager tests clipboard operations
func TestClipboardManager(t *testing.T) {
	cm := utils.NewClipboardManager(100 * time.Millisecond)

	// Test copy
	testContent := "test-clipboard-content"
	if err := cm.Copy(testContent); err != nil {
		t.Skipf("Clipboard not available: %v", err)
	}

	// Wait for auto-clear
	time.Sleep(200 * time.Millisecond)

	t.Log("✓ Clipboard manager test passed")
}

// TestCryptoModules tests cryptographic operations
func TestCryptoModules(t *testing.T) {
	// Test encryption/decryption
	t.Log("Testing encryption...")
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	plaintext := []byte("sensitive data to encrypt")
	ciphertext, err := crypto.Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decrypted, err := crypto.Decrypt(ciphertext, key)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Error("Decrypted data doesn't match original")
	}

	// Test key derivation
	t.Log("Testing key derivation...")
	pw := []byte("test-password")
	salt, err := crypto.GenerateSalt()
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	derivedKey := crypto.DeriveKey(pw, salt)
	if len(derivedKey) != 32 {
		t.Errorf("Derived key length mismatch: got %d, want 32", len(derivedKey))
	}

	// Same password + salt = same key
	derivedKey2 := crypto.DeriveKey(pw, salt)
	if string(derivedKey) != string(derivedKey2) {
		t.Error("Key derivation is not deterministic")
	}

	// Different salt = different key
	salt2, _ := crypto.GenerateSalt()
	derivedKey3 := crypto.DeriveKey(pw, salt2)
	if string(derivedKey) == string(derivedKey3) {
		t.Error("Different salts should produce different keys")
	}

	// Test MEK bundle
	t.Log("Testing MEK bundle...")
	bundle, phrase, err := crypto.CreateMEKBundle("test-password")
	if err != nil {
		t.Fatalf("Failed to create MEK bundle: %v", err)
	}

	mek1, err := bundle.DecryptMEKWithPassword("test-password")
	if err != nil {
		t.Fatalf("Failed to decrypt MEK with password: %v", err)
	}

	mek2, err := bundle.DecryptMEKWithPhrase(phrase)
	if err != nil {
		t.Fatalf("Failed to decrypt MEK with phrase: %v", err)
	}

	if string(mek1) != string(mek2) {
		t.Error("MEK from password and phrase don't match")
	}

	t.Log("✓ Crypto modules test passed")
}

// TestSearch tests entry search functionality
func TestSearch(t *testing.T) {
	resetMockKeyring()
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "test.vault")
	password := "test-password"

	v, _, err := vault.Create(vaultPath, password)
	if err != nil {
		t.Fatalf("Failed to create vault: %v", err)
	}

	// Add entries with various data
	testEntries := []struct {
		title    string
		username string
	}{
		{"GitHub Personal", "user1@github.com"},
		{"GitHub Work", "user2@github.com"},
		{"Gmail", "user@gmail.com"},
		{"Work Email", "user@work.com"},
	}

	for _, e := range testEntries {
		entry := vault.NewEntry(e.title)
		entry.Username = e.username
		v.AddEntry(entry)
	}

	// Test search by title
	github := v.Search("github")
	if len(github) != 2 {
		t.Errorf("Expected 2 GitHub entries, got %d", len(github))
	}

	// Test search by username
	gmailEntries := v.Search("gmail")
	if len(gmailEntries) != 1 {
		t.Errorf("Expected 1 gmail entry, got %d", len(gmailEntries))
	}

	v.Lock()
	t.Log("✓ Search test passed")
}

// TestConcurrentAccess tests thread safety
func TestConcurrentAccess(t *testing.T) {
	resetMockKeyring()
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "test.vault")
	password := "test-password"

	v, _, err := vault.Create(vaultPath, password)
	if err != nil {
		t.Fatalf("Failed to create vault: %v", err)
	}

	// Add initial entry
	entry := vault.NewEntry("Test")
	v.AddEntry(entry)

	// Concurrent reads
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				_ = v.Entries()
				_ = v.EntryCount()
			}
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	v.Lock()
	t.Log("✓ Concurrent access test passed")
}
