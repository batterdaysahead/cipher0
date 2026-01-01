// Package vault provides vault management for the password manager.
package vault

import (
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/batterdaysahead/cipher0/internal/crypto"
)

var (
	// ErrVaultLocked is returned when attempting operations on a locked vault.
	ErrVaultLocked = errors.New("vault is locked")
	// ErrVaultNotFound is returned when the vault file doesn't exist.
	ErrVaultNotFound = errors.New("vault not found")
	// ErrWrongPassword is returned when the password is incorrect.
	ErrWrongPassword = errors.New("incorrect password")
	// ErrWrongPhrase is returned when the recovery phrase is incorrect.
	ErrWrongPhrase = errors.New("incorrect recovery phrase")
	// ErrEntryNotFound is returned when an entry is not found.
	ErrEntryNotFound = errors.New("entry not found")
	// ErrDuplicateEntry is returned when adding a duplicate entry.
	ErrDuplicateEntry = errors.New("entry with this ID already exists")
)

// VaultData represents the decrypted vault data.
type VaultData struct {
	Entries EntryList `json:"entries"`
}

// Vault represents an unlocked password vault.
type Vault struct {
	mu       sync.RWMutex
	path     string
	mek      *crypto.SecureMEK
	db       *Database
	data     *VaultData
	modified bool
}

// Create creates a new vault with the given password.
// Returns the vault, recovery phrase, and any error.
// The recovery phrase must be shown to the user and is not stored.
func Create(path, password string) (*Vault, string, error) {
	bundle, phrase, err := crypto.CreateMEKBundle(password)
	if err != nil {
		return nil, "", err
	}

	data := &VaultData{
		Entries: make(EntryList, 0),
	}

	mekBytes, err := bundle.DecryptMEKWithPassword(password)
	if err != nil {
		return nil, "", err
	}

	// Build DB first so BuildAAD() is available
	keyringFingerprint := crypto.GetKeyringFingerprint()
	db := NewDatabase(
		bundle.SaltPassword,
		bundle.SaltPhrase,
		bundle.EncryptedMEKPassword,
		bundle.EncryptedMEKPhrase,
		nil, // encrypted data will be set below
		SecurityModePasswordKeyring,
		keyringFingerprint,
	)

	dataJSON, err := json.Marshal(data)
	if err != nil {
		crypto.ZeroMemory(mekBytes)
		return nil, "", err
	}

	// Encrypt with AAD
	aad := db.BuildAAD()
	encryptedData, err := crypto.EncryptWithAAD(dataJSON, mekBytes, aad)
	if err != nil {
		crypto.ZeroMemory(mekBytes)
		return nil, "", err
	}

	db.SetEncryptedData(encryptedData)

	if err := SaveDatabase(db, path); err != nil {
		crypto.ZeroMemory(mekBytes)
		return nil, "", err
	}

	// Wrap MEK in secure memory (this wipes mekBytes)
	mek := crypto.NewSecureMEK(mekBytes)

	vault := &Vault{
		path:     path,
		mek:      mek,
		db:       db,
		data:     data,
		modified: false,
	}

	return vault, phrase, nil
}

// UnlockWithPassword unlocks an existing vault with the master password.
func UnlockWithPassword(path, password string) (*Vault, error) {
	db, err := LoadDatabase(path)
	if err != nil {
		if errors.Is(err, ErrDatabaseNotFound) {
			return nil, ErrVaultNotFound
		}
		return nil, err
	}

	salt, err := db.GetSaltPassword()
	if err != nil {
		return nil, err
	}

	encMEK, err := db.GetEncryptedMEKPassword()
	if err != nil {
		return nil, err
	}

	// Get keyring secret
	keyringSecret, kerr := crypto.GetKeyringSecret()
	if keyringSecret != nil {
		defer crypto.ZeroMemory(keyringSecret)
	}

	// Derive key (with keyring if available)
	var key []byte
	if kerr == nil && keyringSecret != nil {
		key = crypto.DeriveKeyWithKeyring([]byte(password), salt, keyringSecret)
	} else {
		key = crypto.DeriveKey([]byte(password), salt)
	}
	defer crypto.ZeroMemory(key)

	mekBytes, err := crypto.DecryptMEK(encMEK, key)
	if err != nil {
		if errors.Is(err, crypto.ErrMEKDecryptionFailed) {
			return nil, ErrWrongPassword
		}
		return nil, err
	}

	data, err := decryptVaultData(db, mekBytes)
	if err != nil {
		crypto.ZeroMemory(mekBytes)
		return nil, err
	}

	// Wrap MEK in secure memory (this wipes mekBytes)
	mek := crypto.NewSecureMEK(mekBytes)

	return &Vault{
		path:     path,
		mek:      mek,
		db:       db,
		data:     data,
		modified: false,
	}, nil
}

// UnlockWithPhrase unlocks an existing vault with the recovery phrase.
func UnlockWithPhrase(path, phrase string) (*Vault, error) {
	db, err := LoadDatabase(path)
	if err != nil {
		if errors.Is(err, ErrDatabaseNotFound) {
			return nil, ErrVaultNotFound
		}
		return nil, err
	}

	phraseKey, err := crypto.PhraseToKey(phrase)
	if err != nil {
		return nil, ErrWrongPhrase
	}
	defer crypto.ZeroMemory(phraseKey)

	encMEK, err := db.GetEncryptedMEKPhrase()
	if err != nil {
		return nil, err
	}

	mekBytes, err := crypto.DecryptMEK(encMEK, phraseKey)
	if err != nil {
		if errors.Is(err, crypto.ErrMEKDecryptionFailed) {
			return nil, ErrWrongPhrase
		}
		return nil, err
	}

	data, err := decryptVaultData(db, mekBytes)
	if err != nil {
		crypto.ZeroMemory(mekBytes)
		return nil, err
	}

	// Wrap MEK in secure memory (this wipes mekBytes)
	mek := crypto.NewSecureMEK(mekBytes)

	return &Vault{
		path:     path,
		mek:      mek,
		db:       db,
		data:     data,
		modified: false,
	}, nil
}

// decryptVaultData decrypts the vault data using the MEK.
// Tries AAD-authenticated decryption first, falls back to legacy for migration.
func decryptVaultData(db *Database, mek []byte) (*VaultData, error) {
	encData, err := db.GetEncryptedData()
	if err != nil {
		return nil, err
	}

	// Try AAD-authenticated decryption first
	aad := db.BuildAAD()
	dataJSON, err := crypto.DecryptWithAAD(encData, mek, aad)
	if err != nil {
		// Fall back to legacy decryption for vaults created before AAD
		dataJSON, err = crypto.Decrypt(encData, mek)
		if err != nil {
			return nil, err
		}
	}
	defer crypto.ZeroMemory(dataJSON)

	var data VaultData
	if err := json.Unmarshal(dataJSON, &data); err != nil {
		return nil, err
	}

	if data.Entries == nil {
		data.Entries = make(EntryList, 0)
	}

	return &data, nil
}

// Save saves the vault to disk.
func (v *Vault) Save() error {
	v.mu.Lock()
	defer v.mu.Unlock()

	return v.saveLocked()
}

func (v *Vault) saveLocked() error {
	dataJSON, err := json.Marshal(v.data)
	if err != nil {
		return err
	}
	defer crypto.ZeroMemory(dataJSON)

	// Encrypt with AAD to bind data to header metadata
	aad := v.db.BuildAAD()
	mekBytes, mekCleanup, err := v.mek.Bytes()
	if err != nil {
		return err
	}
	defer mekCleanup()
	encData, err := crypto.EncryptWithAAD(dataJSON, mekBytes, aad)
	if err != nil {
		return err
	}

	v.db.SetEncryptedData(encData)

	if err := SaveDatabase(v.db, v.path); err != nil {
		return err
	}

	v.modified = false
	return nil
}

// Lock destroys the MEK and closes the vault.
func (v *Vault) Lock() {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.mek != nil {
		v.mek.Destroy()
		v.mek = nil
	}
	v.data = nil
}

// IsLocked returns true if the vault is locked.
func (v *Vault) IsLocked() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.mek == nil || v.mek.IsDestroyed()
}

// IsModified returns true if the vault has unsaved changes.
func (v *Vault) IsModified() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.modified
}

// Path returns the vault file path.
func (v *Vault) Path() string {
	return v.path
}

// Entries returns a copy of all entries.
func (v *Vault) Entries() EntryList {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.data == nil {
		return nil
	}

	entries := make(EntryList, len(v.data.Entries))
	copy(entries, v.data.Entries)
	return entries
}

// EntryCount returns the number of entries.
func (v *Vault) EntryCount() int {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.data == nil {
		return 0
	}
	return len(v.data.Entries)
}

// GetEntry returns an entry by ID.
func (v *Vault) GetEntry(id string) (*Entry, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.data == nil {
		return nil, ErrVaultLocked
	}

	entry := v.data.Entries.FindByID(id)
	if entry == nil {
		return nil, ErrEntryNotFound
	}

	return entry, nil
}

// AddEntry adds a new entry to the vault.
func (v *Vault) AddEntry(entry *Entry) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.data == nil {
		return ErrVaultLocked
	}

	if v.data.Entries.FindByID(entry.ID) != nil {
		return ErrDuplicateEntry
	}

	v.data.Entries = append(v.data.Entries, entry)
	v.modified = true
	return nil
}

// UpdateEntry updates an existing entry.
func (v *Vault) UpdateEntry(entry *Entry) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.data == nil {
		return ErrVaultLocked
	}

	for i, e := range v.data.Entries {
		if e.ID == entry.ID {
			entry.Update()
			v.data.Entries[i] = entry
			v.modified = true
			return nil
		}
	}

	return ErrEntryNotFound
}

// DeleteEntry removes an entry by ID.
func (v *Vault) DeleteEntry(id string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.data == nil {
		return ErrVaultLocked
	}

	for i, e := range v.data.Entries {
		if e.ID == id {
			v.data.Entries = append(v.data.Entries[:i], v.data.Entries[i+1:]...)
			v.modified = true
			return nil
		}
	}

	return ErrEntryNotFound
}

// Search searches entries by query.
func (v *Vault) Search(query string) EntryList {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.data == nil {
		return nil
	}

	return v.data.Entries.Search(query)
}

// ChangePassword changes the master password.
func (v *Vault) ChangePassword(oldPassword, newPassword string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.mek == nil || v.mek.IsDestroyed() {
		return ErrVaultLocked
	}

	salt, err := v.db.GetSaltPassword()
	if err != nil {
		return err
	}

	encMEK, err := v.db.GetEncryptedMEKPassword()
	if err != nil {
		return err
	}

	// Get keyring secret
	keyringSecret, kerr := crypto.GetKeyringSecret()
	if keyringSecret != nil {
		defer crypto.ZeroMemory(keyringSecret)
	}

	var oldKey []byte
	if kerr == nil && keyringSecret != nil {
		oldKey = crypto.DeriveKeyWithKeyring([]byte(oldPassword), salt, keyringSecret)
	} else {
		oldKey = crypto.DeriveKey([]byte(oldPassword), salt)
	}
	defer crypto.ZeroMemory(oldKey)

	_, err = crypto.DecryptMEK(encMEK, oldKey)
	if err != nil {
		return ErrWrongPassword
	}

	// Generate new salt and encrypt MEK with new password
	newSalt, err := crypto.GenerateSalt()
	if err != nil {
		return err
	}

	// Derive new key (with keyring if available)
	var newKey []byte
	if kerr == nil && keyringSecret != nil {
		newKey = crypto.DeriveKeyWithKeyring([]byte(newPassword), newSalt, keyringSecret)
	} else {
		newKey = crypto.DeriveKey([]byte(newPassword), newSalt)
	}
	defer crypto.ZeroMemory(newKey)

	mekBytes, mekCleanup, err := v.mek.Bytes()
	if err != nil {
		return err
	}
	defer mekCleanup()
	newEncMEK, err := crypto.EncryptMEK(mekBytes, newKey)
	if err != nil {
		return err
	}

	v.db.UpdateMEKPassword(newSalt, newEncMEK)
	return v.saveLocked()
}

// SetNewPassword sets a new master password without requiring the old password.
// This is used after phrase-based recovery where the old password is not available.
func (v *Vault) SetNewPassword(newPassword string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.mek == nil || v.mek.IsDestroyed() {
		return ErrVaultLocked
	}

	// Generate new salt and encrypt MEK with new password
	newSalt, err := crypto.GenerateSalt()
	if err != nil {
		return err
	}

	keyringSecret, kerr := crypto.GetOrCreateKeyringSecret()
	if keyringSecret != nil {
		defer crypto.ZeroMemory(keyringSecret)
	}

	// Derive new key (with keyring if available)
	var newKey []byte
	if kerr == nil && keyringSecret != nil {
		newKey = crypto.DeriveKeyWithKeyring([]byte(newPassword), newSalt, keyringSecret)
	} else {
		newKey = crypto.DeriveKey([]byte(newPassword), newSalt)
	}
	defer crypto.ZeroMemory(newKey)

	mekBytes, mekCleanup, err := v.mek.Bytes()
	if err != nil {
		return err
	}
	defer mekCleanup()
	newEncMEK, err := crypto.EncryptMEK(mekBytes, newKey)
	if err != nil {
		return err
	}

	v.db.UpdateMEKPassword(newSalt, newEncMEK)

	// Update fingerprint after recovery since keyring may have changed
	v.db.KeyringFingerprint = crypto.GetKeyringFingerprint()
	v.db.SecurityMode = SecurityModePasswordKeyring

	return v.saveLocked()
}

// LastBackup returns the last backup timestamp.
func (v *Vault) LastBackup() *time.Time {
	v.mu.RLock()
	defer v.mu.RUnlock()

	return v.db.LastBackup
}

// VerifyPassword verifies that the provided password is correct.
// Returns nil if the password is correct, ErrWrongPassword otherwise.
func (v *Vault) VerifyPassword(password string) error {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.mek == nil || v.mek.IsDestroyed() {
		return ErrVaultLocked
	}

	salt, err := v.db.GetSaltPassword()
	if err != nil {
		return err
	}

	encMEK, err := v.db.GetEncryptedMEKPassword()
	if err != nil {
		return err
	}

	// Get keyring secret
	keyringSecret, kerr := crypto.GetKeyringSecret()
	if keyringSecret != nil {
		defer crypto.ZeroMemory(keyringSecret)
	}

	// Derive key (with keyring if available)
	var key []byte
	if kerr == nil && keyringSecret != nil {
		key = crypto.DeriveKeyWithKeyring([]byte(password), salt, keyringSecret)
	} else {
		key = crypto.DeriveKey([]byte(password), salt)
	}
	defer crypto.ZeroMemory(key)

	_, err = crypto.DecryptMEK(encMEK, key)
	if err != nil {
		return ErrWrongPassword
	}

	return nil
}

// VerifyPhrase verifies that the provided recovery phrase is correct.
// Returns nil if the phrase is correct, ErrWrongPhrase otherwise.
func (v *Vault) VerifyPhrase(phrase string) error {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.mek == nil || v.mek.IsDestroyed() {
		return ErrVaultLocked
	}

	// Derive key from phrase
	phraseKey, err := crypto.PhraseToKey(phrase)
	if err != nil {
		return ErrWrongPhrase
	}
	defer crypto.ZeroMemory(phraseKey)

	encMEK, err := v.db.GetEncryptedMEKPhrase()
	if err != nil {
		return err
	}

	_, err = crypto.DecryptMEK(encMEK, phraseKey)
	if err != nil {
		return ErrWrongPhrase
	}

	return nil
}
