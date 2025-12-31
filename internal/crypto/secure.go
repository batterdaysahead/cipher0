// Package crypto provides cryptographic operations for the password manager.
package crypto

import (
	"github.com/awnumar/memguard"
)

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

// Bytes opens the Enclave and returns the key. Caller must call cleanup().
//
//	key, cleanup := mek.Bytes()
//	defer cleanup()
func (s *SecureMEK) Bytes() ([]byte, func()) {
	if s == nil || s.enclave == nil {
		return nil, func() {}
	}

	buf, err := s.enclave.Open()
	if err != nil {
		return nil, func() {}
	}

	return buf.Bytes(), func() { buf.Destroy() }
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

// SafePanic wipes memory and panics.
func SafePanic(v interface{}) {
	memguard.SafePanic(v)
}
