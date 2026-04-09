// keys_test.go
// =============================================================================
// GRUG: Tests for the keys cave. Generate, load, refuse duplicate, bad input.
// =============================================================================

package keys

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
)

// TestGenerateAndLoad generates a keypair and loads both halves back.
func TestGenerateAndLoad(t *testing.T) {
	dir := t.TempDir()

	kp, err := Generate(dir, "testkey")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if len(kp.PrivateKey) != ed25519.PrivateKeySize {
		t.Errorf("private key wrong size: got %d", len(kp.PrivateKey))
	}
	if len(kp.PublicKey) != ed25519.PublicKeySize {
		t.Errorf("public key wrong size: got %d", len(kp.PublicKey))
	}

	// Load private key from disk and verify it matches
	priv, err := LoadPrivateKey(kp.PrivPath)
	if err != nil {
		t.Fatalf("LoadPrivateKey: %v", err)
	}
	if !priv.Equal(kp.PrivateKey) {
		t.Error("loaded private key doesn't match generated key")
	}

	// Load public key from disk and verify it matches
	pub, err := LoadPublicKey(kp.PubPath)
	if err != nil {
		t.Fatalf("LoadPublicKey: %v", err)
	}
	if !pub.Equal(kp.PublicKey) {
		t.Error("loaded public key doesn't match generated key")
	}
}

// TestGenerateRefusesOverwrite verifies Generate returns an error if the key
// already exists, rather than silently overwriting.
func TestGenerateRefusesOverwrite(t *testing.T) {
	dir := t.TempDir()

	if _, err := Generate(dir, "mykey"); err != nil {
		t.Fatalf("first Generate: %v", err)
	}

	_, err := Generate(dir, "mykey")
	if err == nil {
		t.Fatal("expected error on duplicate Generate, got nil")
	}
	t.Logf("correctly refused overwrite: %v", err)
}

// TestLoadPrivateKeyBadFile verifies LoadPrivateKey returns a FATAL error
// for a non-PEM file.
func TestLoadPrivateKeyBadFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.key")
	os.WriteFile(path, []byte("this is not PEM"), 0600)

	_, err := LoadPrivateKey(path)
	if err == nil {
		t.Fatal("expected error loading bad key file, got nil")
	}
}

// TestLoadPrivateKeyWrongType verifies LoadPrivateKey rejects a PEM block
// with the wrong type header.
func TestLoadPrivateKeyWrongType(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wrong.key")
	// Write a PEM block with wrong type
	pem := "-----BEGIN WRONG TYPE-----\nYWJj\n-----END WRONG TYPE-----\n"
	os.WriteFile(path, []byte(pem), 0600)

	_, err := LoadPrivateKey(path)
	if err == nil {
		t.Fatal("expected error for wrong PEM type, got nil")
	}
}

// TestLoadMissingFile verifies Load functions return errors for missing files.
func TestLoadMissingFile(t *testing.T) {
	_, err := LoadPrivateKey("/does/not/exist.key")
	if err == nil {
		t.Fatal("expected error for missing private key file")
	}

	_, err = LoadPublicKey("/does/not/exist.pub")
	if err == nil {
		t.Fatal("expected error for missing public key file")
	}
}

// TestSignVerifyRoundtrip verifies that a key generated with Generate can
// sign and verify data correctly (end-to-end key sanity check).
func TestSignVerifyRoundtrip(t *testing.T) {
	dir := t.TempDir()
	kp, err := Generate(dir, "sigtest")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	message := []byte("bindboss payload hash goes here")
	sig := ed25519.Sign(kp.PrivateKey, message)

	if !ed25519.Verify(kp.PublicKey, message, sig) {
		t.Fatal("Ed25519 sign/verify roundtrip failed")
	}
}

// TestPrivKeyFilePermissions verifies the private key file is written with
// mode 0600 (owner read/write only).
func TestPrivKeyFilePermissions(t *testing.T) {
	dir := t.TempDir()
	kp, err := Generate(dir, "permtest")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	fi, err := os.Stat(kp.PrivPath)
	if err != nil {
		t.Fatalf("stat priv key: %v", err)
	}

	mode := fi.Mode().Perm()
	if mode != 0600 {
		t.Errorf("private key file permissions: got %o, want 0600", mode)
	}
}