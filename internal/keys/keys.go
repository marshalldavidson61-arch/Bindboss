// keys.go
// =============================================================================
// GRUG: grug need key to sign binary. this cave make key. keep key safe.
// grug run "keygen myproject" once. get two files: .key (secret) and .pub (share).
// .key sign payload at pack time. .pub verify at any time.
// lose .key = cannot verify old binaries. bad. very bad. don't lose key.
//
// GRUG: grug refuse to overwrite existing key. overwrite = disaster.
// if you want new key, delete old one yourself. grug not do it for you.
//
// GRUG: private key file mode 0600 — owner only. not 0644. not 0777.
// if grug see wrong permissions, whole signing chain is sus.
//
// -----------------------------------------------------------------------------
// ACADEMIC FOOTER:
// Keys are Ed25519 (RFC 8032), a Schnorr-variant signature scheme over
// Curve25519. Key generation draws 32 bytes from crypto/rand (CSPRNG).
// Go's ed25519.PrivateKey is 64 bytes: seed (32) || public key (32).
//
// Keys are stored as PEM blocks with type "BINDBOSS PRIVATE KEY" /
// "BINDBOSS PUBLIC KEY" rather than PKCS#8 "PRIVATE KEY" to avoid confusion
// with TLS/SSH key formats and make the bindboss origin unambiguous.
//
// The signature operation is: Sign(privKey, SHA-256(payload)). Signing the
// hash rather than the raw payload is safe for collision-resistant hash
// functions and avoids loading the full payload into memory at sign time.
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

// KeyPair is what you get back from Generate.
type KeyPair struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
	PrivPath   string
	PubPath    string
}

// DefaultKeyDir returns ~/.bindboss/keys/ — where grug keeps keys by default.
func DefaultKeyDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("!!! FATAL: cannot determine home directory: %w", err)
	}
	return filepath.Join(home, ".bindboss", "keys"), nil
}

// Generate creates a new Ed25519 keypair and writes it to keyDir/<name>.key and .pub.
// Returns FATAL if key already exists — grug does not silently overwrite.
func Generate(keyDir, name string) (*KeyPair, error) {
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return nil, fmt.Errorf("!!! FATAL: cannot create key directory %q: %w", keyDir, err)
	}

	privPath := filepath.Join(keyDir, name+".key")
	pubPath := filepath.Join(keyDir, name+".pub")

	// GRUG: key exists = stop. overwriting key = all old signatures unverifiable. no.
	if _, err := os.Stat(privPath); err == nil {
		return nil, fmt.Errorf(
			"!!! FATAL: key %q already exists at %s — delete it manually to regenerate", name, privPath)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("!!! FATAL: key generation failed: %w", err)
	}

	// GRUG: 0600 = owner read/write only. private key must not be world-readable.
	privPEM := pem.EncodeToMemory(&pem.Block{Type: pemTypePrivate, Bytes: []byte(priv)})
	if err := os.WriteFile(privPath, privPEM, 0600); err != nil {
		return nil, fmt.Errorf("!!! FATAL: cannot write private key to %q: %w", privPath, err)
	}

	pubPEM := pem.EncodeToMemory(&pem.Block{Type: pemTypePublic, Bytes: []byte(pub)})
	if err := os.WriteFile(pubPath, pubPEM, 0644); err != nil {
		// GRUG: pub write failed — remove priv so we don't leave orphaned private key
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

// LoadPrivateKey reads an Ed25519 private key from a PEM file.
// Wrong type, wrong size, missing file = FATAL. No silent guessing.
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
	if len(block.Bytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf(
			"!!! FATAL: private key in %q has wrong size %d (expected %d)",
			path, len(block.Bytes), ed25519.PrivateKeySize)
	}

	return ed25519.PrivateKey(block.Bytes), nil
}

// LoadPublicKey reads an Ed25519 public key from a PEM file.
// Wrong type, wrong size, missing file = FATAL.
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