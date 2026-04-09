// keys.go
// =============================================================================
// GRUG: This is the keys cave. Generates and loads Ed25519 keypairs for
// signing packed binaries. Keys live in ~/.bindboss/keys/ as PEM files.
//
// ACADEMIC: Ed25519 (RFC 8032) is a Schnorr-variant signature scheme over
// Curve25519. Key generation is O(1) and deterministic from a 32-byte seed.
// Public keys are 32 bytes; private keys (in Go's representation) are 64 bytes
// (seed || public key). We store them as PEM blocks for human readability and
// standard tooling compatibility.
//
// We use PEM type "BINDBOSS PRIVATE KEY" and "BINDBOSS PUBLIC KEY" rather than
// "PRIVATE KEY" (PKCS#8) to avoid confusion with X.509 key formats and make
// clear these are bindboss-specific keys, not TLS/SSH keys.
// =============================================================================

package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

const (
	pemTypePrivate = "BINDBOSS PRIVATE KEY"
	pemTypePublic  = "BINDBOSS PUBLIC KEY"
)

// KeyPair holds an Ed25519 keypair loaded from or written to disk.
type KeyPair struct {
	// PrivateKey is the full 64-byte Ed25519 private key (seed || public).
	PrivateKey ed25519.PrivateKey

	// PublicKey is the 32-byte Ed25519 public key.
	PublicKey ed25519.PublicKey

	// PrivPath is the path where the private key was loaded from or saved to.
	PrivPath string

	// PubPath is the path where the public key was loaded from or saved to.
	PubPath string
}

// DefaultKeyDir returns the default directory for bindboss keys:
// ~/.bindboss/keys/
func DefaultKeyDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("!!! FATAL: cannot determine home directory: %w", err)
	}
	return filepath.Join(home, ".bindboss", "keys"), nil
}

// Generate creates a new Ed25519 keypair, saves it to keyDir/<name>.key and
// keyDir/<name>.pub, and returns the KeyPair. Returns an error if the key
// already exists (no silent overwrite — overwriting a key is irreversible).
func Generate(keyDir, name string) (*KeyPair, error) {
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return nil, fmt.Errorf("!!! FATAL: cannot create key directory %q: %w", keyDir, err)
	}

	privPath := filepath.Join(keyDir, name+".key")
	pubPath := filepath.Join(keyDir, name+".pub")

	// GRUG: Refuse to overwrite existing keys. Losing a private key means all
	// binaries signed with it can no longer be verified. Make the user decide.
	if _, err := os.Stat(privPath); err == nil {
		return nil, fmt.Errorf(
			"!!! FATAL: key %q already exists at %s — delete it manually to regenerate", name, privPath)
	}

	// ACADEMIC: ed25519.GenerateKey reads 32 bytes from crypto/rand (CSPRNG).
	// The returned private key is the 64-byte concatenation (seed || public key).
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("!!! FATAL: key generation failed: %w", err)
	}

	// Write private key (mode 0600 — owner read/write only)
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  pemTypePrivate,
		Bytes: []byte(priv),
	})
	if err := os.WriteFile(privPath, privPEM, 0600); err != nil {
		return nil, fmt.Errorf("!!! FATAL: cannot write private key to %q: %w", privPath, err)
	}

	// Write public key (mode 0644 — world-readable, safe to distribute)
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  pemTypePublic,
		Bytes: []byte(pub),
	})
	if err := os.WriteFile(pubPath, pubPEM, 0644); err != nil {
		// GRUG: Clean up the private key if we can't write the public key.
		// A private key without its matching public key is a footgun.
		os.Remove(privPath)
		return nil, fmt.Errorf("!!! FATAL: cannot write public key to %q: %w", pubPath, err)
	}

	return &KeyPair{
		PrivateKey: priv,
		PublicKey:  pub,
		PrivPath:   privPath,
		PubPath:    pubPath,
	}, nil
}

// LoadPrivateKey reads an Ed25519 private key from a PEM file at path.
// Returns an error if the file is missing, malformed, or the wrong type.
// No silent failures — a bad key file means signing is broken.
func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("!!! FATAL: cannot read private key %q: %w", path, err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("!!! FATAL: %q is not a valid PEM file", path)
	}
	if block.Type != pemTypePrivate {
		return nil, fmt.Errorf(
			"!!! FATAL: %q has PEM type %q, expected %q", path, block.Type, pemTypePrivate)
	}

	// ACADEMIC: Ed25519 private key in Go is 64 bytes: seed (32) || public (32).
	if len(block.Bytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf(
			"!!! FATAL: private key in %q has wrong size %d (expected %d)",
			path, len(block.Bytes), ed25519.PrivateKeySize)
	}

	return ed25519.PrivateKey(block.Bytes), nil
}

// LoadPublicKey reads an Ed25519 public key from a PEM file at path.
// Returns an error if the file is missing, malformed, or the wrong type.
func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("!!! FATAL: cannot read public key %q: %w", path, err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("!!! FATAL: %q is not a valid PEM file", path)
	}
	if block.Type != pemTypePublic {
		return nil, fmt.Errorf(
			"!!! FATAL: %q has PEM type %q, expected %q", path, block.Type, pemTypePublic)
	}

	if len(block.Bytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf(
			"!!! FATAL: public key in %q has wrong size %d (expected %d)",
			path, len(block.Bytes), ed25519.PublicKeySize)
	}

	return ed25519.PublicKey(block.Bytes), nil
}