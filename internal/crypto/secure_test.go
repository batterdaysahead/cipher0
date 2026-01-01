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

	retrieved, cleanup, err := mek.Bytes()
	if err != nil {
		t.Fatalf("Bytes() error: %v", err)
	}
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

	_, _, err := mek.Bytes()
	if err != ErrMEKUnavailable {
		t.Errorf("got %v, want ErrMEKUnavailable", err)
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
	_, _, err := nilMEK.Bytes()
	if err != ErrMEKUnavailable {
		t.Errorf("got %v, want ErrMEKUnavailable", err)
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
		retrieved, cleanup, err := mek.Bytes()
		if err != nil {
			t.Fatalf("access %d: %v", i, err)
		}
		if len(retrieved) != 32 {
			t.Errorf("access %d: got %d bytes", i, len(retrieved))
		}
		cleanup()
	}
}

func TestSecureMEKCleanupIdempotent(t *testing.T) {
	mek := NewSecureMEK(make([]byte, 32))
	defer mek.Destroy()

	_, cleanup, err := mek.Bytes()
	if err != nil {
		t.Fatalf("Bytes() error: %v", err)
	}
	cleanup()
	cleanup() // should not panic
}
