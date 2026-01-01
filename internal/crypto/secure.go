// Package crypto provides cryptographic operations for the password manager.
package crypto

import (
	"errors"

	"github.com/awnumar/memguard"
)

// ErrMEKUnavailable is returned when the MEK cannot be decrypted from the Enclave.
var ErrMEKUnavailable = errors.New("MEK unavailable: enclave may be corrupted")

// SecureMEK stores the MEK in an encrypted Enclave.
// Only decrypted briefly when needed for crypto ops.
type SecureMEK struct {
	enclave *memguard.Enclave
}

// NewSecureMEK seals key into an Enclave. Wipes source bytes.
func NewSecureMEK(key []byte) *SecureMEK {
	if len(key) == 0 {
		return nil
	}

	buf := memguard.NewBufferFromBytes(key)
	enclave := buf.Seal()

	return &SecureMEK{enclave: enclave}
}

// Bytes opens the Enclave and returns the key.
// Returns ErrMEKUnavailable if the enclave cannot be opened.
// Caller must call cleanup() when done.
//
//	key, cleanup, err := mek.Bytes()
//	if err != nil { return err }
//	defer cleanup()
func (s *SecureMEK) Bytes() ([]byte, func(), error) {
	if s == nil || s.enclave == nil {
		return nil, func() {}, ErrMEKUnavailable
	}

	buf, err := s.enclave.Open()
	if err != nil {
		return nil, func() {}, ErrMEKUnavailable
	}

	return buf.Bytes(), func() { buf.Destroy() }, nil
}

// Destroy releases the Enclave.
func (s *SecureMEK) Destroy() {
	if s != nil && s.enclave != nil {
		s.enclave = nil
	}
}

// IsDestroyed returns true if destroyed or nil.
func (s *SecureMEK) IsDestroyed() bool {
	return s == nil || s.enclave == nil
}

// SafeExit wipes all memguard data and exits.
func SafeExit() {
	memguard.SafeExit(0)
}
