package crypto

import (
	"bytes"
	"testing"
)

func TestNewSecureMEK(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	mek := NewSecureMEK(key)
	if mek == nil {
		t.Fatal("got nil")
	}
	defer mek.Destroy()

	retrieved, cleanup := mek.Bytes()
	defer cleanup()

	if len(retrieved) != 32 {
		t.Errorf("got %d bytes, want 32", len(retrieved))
	}

	expected := make([]byte, 32)
	for i := range expected {
		expected[i] = byte(i)
	}
	if !bytes.Equal(retrieved, expected) {
		t.Error("bytes mismatch")
	}
}

func TestNewSecureMEKEmpty(t *testing.T) {
	if NewSecureMEK(nil) != nil {
		t.Error("nil input should return nil")
	}
	if NewSecureMEK([]byte{}) != nil {
		t.Error("empty input should return nil")
	}
}

func TestSecureMEKDestroy(t *testing.T) {
	mek := NewSecureMEK(make([]byte, 32))
	mek.Destroy()

	if !mek.IsDestroyed() {
		t.Error("should be destroyed")
	}

	retrieved, cleanup := mek.Bytes()
	defer cleanup()
	if retrieved != nil {
		t.Error("Bytes() should return nil after Destroy()")
	}
}

func TestSecureMEKIsDestroyed(t *testing.T) {
	var nilMEK *SecureMEK
	if !nilMEK.IsDestroyed() {
		t.Error("nil should be destroyed")
	}

	mek := NewSecureMEK(make([]byte, 32))
	if mek.IsDestroyed() {
		t.Error("new MEK shouldn't be destroyed")
	}

	mek.Destroy()
	if !mek.IsDestroyed() {
		t.Error("should be destroyed after Destroy()")
	}
}

func TestSecureMEKBytesNil(t *testing.T) {
	var nilMEK *SecureMEK
	retrieved, cleanup := nilMEK.Bytes()
	defer cleanup()

	if retrieved != nil {
		t.Error("nil MEK should return nil bytes")
	}
}

func TestSecureMEKMultipleAccess(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i * 2)
	}

	mek := NewSecureMEK(key)
	defer mek.Destroy()

	for i := 0; i < 3; i++ {
		retrieved, cleanup := mek.Bytes()
		if len(retrieved) != 32 {
			t.Errorf("access %d: got %d bytes", i, len(retrieved))
		}
		cleanup()
	}
}

func TestSecureMEKCleanupIdempotent(t *testing.T) {
	mek := NewSecureMEK(make([]byte, 32))
	defer mek.Destroy()

	_, cleanup := mek.Bytes()
	cleanup()
	cleanup() // should not panic
}
