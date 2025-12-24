// Package vault provides vault management for the password manager.
// This includes the vault database structure, entry management, and file operations.
package vault

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/batterdaysahead/cipher0/internal/crypto"
)

var (
	// ErrDatabaseNotFound is returned when the vault database file doesn't exist.
	ErrDatabaseNotFound = errors.New("vault database not found")
	// ErrDatabaseCorrupted is returned when the database file is corrupted.
	ErrDatabaseCorrupted = errors.New("vault database is corrupted")
	// ErrInvalidVersion is returned when the database version is not supported.
	ErrInvalidVersion = errors.New("unsupported database version")
)

// DatabaseVersion is the current version of the database format.
const DatabaseVersion = "1.1"

// SecurityModePasswordKeyring indicates password + keyring security mode.
// This is the default and only supported mode.
const SecurityModePasswordKeyring = "password_keyring"

// KDFParams contains the parameters for the key derivation function.
type KDFParams struct {
	// Memory is the memory usage in KB.
	Memory uint32 `json:"memory"`
	// Iterations is the number of iterations (time parameter).
	Iterations uint32 `json:"iterations"`
	// Parallelism is the degree of parallelism (threads).
	Parallelism uint8 `json:"parallelism"`
}

// KDFConfig contains the KDF algorithm and its parameters.
type KDFConfig struct {
	// Algorithm is the KDF algorithm name (e.g., "argon2id").
	Algorithm string `json:"algorithm"`
	// Params contains the algorithm-specific parameters.
	Params KDFParams `json:"params"`
}

// Database represents the encrypted vault database structure.
// All sensitive data is stored encrypted with the MEK.
type Database struct {
	// Version is the database format version.
	Version string `json:"version"`
	// SecurityMode indicates the security mode ("password_keyring" or "password_only").
	SecurityMode string `json:"security_mode,omitempty"`
	// KDF contains the key derivation function configuration.
	KDF *KDFConfig `json:"kdf,omitempty"`
	// KeyringFingerprint is the SHA-256 fingerprint of the keyring secret.
	// Used to match keyrings to vaults in multi-vault scenarios.
	KeyringFingerprint string `json:"keyring_fingerprint,omitempty"`
	// SaltPassword is the salt used for password-based key derivation.
	SaltPassword string `json:"salt_password"`
	// SaltPhrase is the salt used for recovery phrase-based key derivation.
	SaltPhrase string `json:"salt_phrase"`
	// EncryptedMEKPassword is the MEK encrypted with the password-derived key.
	EncryptedMEKPassword string `json:"encrypted_mek_password"`
	// EncryptedMEKPhrase is the MEK encrypted with the recovery phrase-derived key.
	EncryptedMEKPhrase string `json:"encrypted_mek_phrase"`
	// EncryptedData is the encrypted vault data (entries).
	EncryptedData string `json:"encrypted_data"`
	// LastBackup is the timestamp of the last backup.
	LastBackup *time.Time `json:"last_backup,omitempty"`
}

// NewDatabase creates a new database with the given MEK bundle and encrypted data.
func NewDatabase(saltPassword, saltPhrase, encMEKPassword, encMEKPhrase, encData []byte, securityMode, keyringFingerprint string) *Database {
	return &Database{
		Version:              DatabaseVersion,
		SecurityMode:         securityMode,
		KDF:                  CurrentKDFConfig(),
		KeyringFingerprint:   keyringFingerprint,
		SaltPassword:         hex.EncodeToString(saltPassword),
		SaltPhrase:           hex.EncodeToString(saltPhrase),
		EncryptedMEKPassword: hex.EncodeToString(encMEKPassword),
		EncryptedMEKPhrase:   hex.EncodeToString(encMEKPhrase),
		EncryptedData:        hex.EncodeToString(encData),
	}
}

// CurrentKDFConfig returns the current KDF configuration.
// Uses constants from crypto package for consistency.
func CurrentKDFConfig() *KDFConfig {
	return &KDFConfig{
		Algorithm: "argon2id",
		Params: KDFParams{
			Memory:      crypto.Argon2Memory,
			Iterations:  crypto.Argon2Time,
			Parallelism: crypto.Argon2Threads,
		},
	}
}

// aadHeader defines fields for canonical AAD serialization.
type aadHeader struct {
	Version      string     `json:"version"`
	SecurityMode string     `json:"security_mode"`
	KDF          *KDFConfig `json:"kdf"`
	SaltPassword string     `json:"salt_password"`
	SaltPhrase   string     `json:"salt_phrase"`
}

// BuildAAD returns canonical header bytes for AAD.
// Tampering with any header field will cause decryption to fail.
func (db *Database) BuildAAD() []byte {
	header := aadHeader{
		Version:      db.Version,
		SecurityMode: db.SecurityMode,
		KDF:          db.KDF,
		SaltPassword: db.SaltPassword,
		SaltPhrase:   db.SaltPhrase,
	}
	data, _ := json.Marshal(header)
	return data
}

// GetSaltPassword returns the decoded salt for password derivation.
func (db *Database) GetSaltPassword() ([]byte, error) {
	return hex.DecodeString(db.SaltPassword)
}

// GetSaltPhrase returns the decoded salt for phrase derivation.
func (db *Database) GetSaltPhrase() ([]byte, error) {
	return hex.DecodeString(db.SaltPhrase)
}

// GetEncryptedMEKPassword returns the decoded encrypted MEK (password).
func (db *Database) GetEncryptedMEKPassword() ([]byte, error) {
	return hex.DecodeString(db.EncryptedMEKPassword)
}

// GetEncryptedMEKPhrase returns the decoded encrypted MEK (phrase).
func (db *Database) GetEncryptedMEKPhrase() ([]byte, error) {
	return hex.DecodeString(db.EncryptedMEKPhrase)
}

// GetEncryptedData returns the decoded encrypted vault data.
func (db *Database) GetEncryptedData() ([]byte, error) {
	return hex.DecodeString(db.EncryptedData)
}

// SetEncryptedData sets the encrypted vault data.
func (db *Database) SetEncryptedData(data []byte) {
	db.EncryptedData = hex.EncodeToString(data)
}

// SetLastBackup updates the last backup timestamp.
func (db *Database) SetLastBackup(t time.Time) {
	db.LastBackup = &t
}

// UpdateMEKPassword updates the password-encrypted MEK and salt.
func (db *Database) UpdateMEKPassword(salt, encMEK []byte) {
	db.SaltPassword = hex.EncodeToString(salt)
	db.EncryptedMEKPassword = hex.EncodeToString(encMEK)
}

// IsPhraseOnly returns true if this database can only be unlocked with recovery phrase.
// This is the case for backup files which have their password fields cleared.
func (db *Database) IsPhraseOnly() bool {
	return db.SaltPassword == "" || db.EncryptedMEKPassword == ""
}

// HasMatchingKeyring checks if the current OS keyring matches the vault's keyring fingerprint.
// Returns true if fingerprints match, false if keyring is missing or different.
func (db *Database) HasMatchingKeyring(currentFingerprint string) bool {
	// If vault has no fingerprint stored (v1.0 migrated), we can't verify
	if db.KeyringFingerprint == "" {
		return currentFingerprint != ""
	}
	return db.KeyringFingerprint == currentFingerprint
}

// RequiresRecoveryPhrase checks if password unlock is not possible due to keyring mismatch.
// Returns true if the keyring is missing or doesn't match the vault's fingerprint.
func (db *Database) RequiresRecoveryPhrase(currentFingerprint string) bool {
	if db.IsPhraseOnly() {
		return true
	}
	// If vault has a fingerprint stored, current keyring must match
	if db.KeyringFingerprint != "" && db.KeyringFingerprint != currentFingerprint {
		return true
	}
	return false
}

// LoadDatabase loads the database from a file.
// Supports automatic migration from v1.0 to v1.1.
func LoadDatabase(path string) (*Database, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrDatabaseNotFound
		}
		return nil, fmt.Errorf("failed to read database: %w", err)
	}

	var db Database
	if err := json.Unmarshal(data, &db); err != nil {
		return nil, ErrDatabaseCorrupted
	}

	if db.Version == "" {
		return nil, ErrDatabaseCorrupted
	}

	// Migrate v1.0 to v1.1 if needed
	switch db.Version {
	case "1.0":
		db.Version = DatabaseVersion
		if db.KDF == nil {
			db.KDF = CurrentKDFConfig()
		}
		if db.SecurityMode == "" {
			db.SecurityMode = SecurityModePasswordKeyring
		}
		// KeyringFingerprint will be populated on next save
	case DatabaseVersion:
	default:
		return nil, ErrInvalidVersion
	}

	return &db, nil
}

// SaveDatabase saves the database to a file with secure permissions.
func SaveDatabase(db *Database, path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	data, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal database: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write database: %w", err)
	}

	return nil
}

// DatabaseExists checks if a database file exists at the given path.
func DatabaseExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// IsPhraseOnlyVault checks if a vault at the given path requires phrase-only unlock.
// This returns true for backup files that have password fields cleared.
func IsPhraseOnlyVault(path string) bool {
	db, err := LoadDatabase(path)
	if err != nil {
		return false
	}
	return db.IsPhraseOnly()
}
