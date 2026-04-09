// keygen.go
// =============================================================================
// GRUG: The keygen command. Make a key. Save it. Use it to sign binaries.
// That is all. One command, two files out: name.key and name.pub.
//
// name.key = PRIVATE. Do not share. Do not commit to git. Do not lose.
//   Losing .key = cannot produce valid signatures for new binaries.
//   Old signed binaries still verifiable with .pub — key loss is not
//   catastrophic for verification, only for future signing.
//
// name.pub = PUBLIC. Share freely. Give to users who will `bindboss verify`.
//   .pub cannot sign anything. Safe to put in a repo, a release page, etc.
//
// Keys live in ~/.bindboss/keys/ by default. --keydir overrides this.
// One keypair per project is the recommended pattern. You can have many.
//
// ---
// ACADEMIC: Bindboss uses Ed25519 (RFC 8032) for payload signing.
// Ed25519 operates over Curve25519 using the Edwards form of the curve.
// Key generation calls crypto/ed25519.GenerateKey(crypto/rand.Reader),
// which samples a 32-byte seed from the OS CSPRNG and derives the private
// scalar and public point deterministically.
//
// Private keys are stored as PEM-encoded PKCS#8 DER (type "PRIVATE KEY").
// Public keys are stored as PEM-encoded PKIX DER (type "PUBLIC KEY").
// These are the standard Go crypto/x509 marshal formats, ensuring
// interoperability with other tools (openssl, ssh-keygen -e -m pkcs8, etc.).
//
// The signing target is SHA-256(payload_bytes), not the raw payload bytes.
// This is safe because SHA-256 is collision-resistant (128-bit security level),
// meaning an adversary cannot construct a different payload with the same hash.
// Signing the hash rather than the full payload avoids loading the entire
// (potentially large) payload into memory at sign and verify time — only
// the 32-byte digest needs to pass through the Ed25519 primitive.
//
// Key files are written with 0600 permissions (owner read/write only).
// This follows the OpenSSH convention for private key files and prevents
// other users on a multi-user system from reading the private key.
// =============================================================================

package cmd

import (
	"flag"
	"fmt"
	"os"

	"github.com/marshalldavidson61-arch/bindboss/internal/keys"
)

// KeygenCmd implements `bindboss keygen`.
type KeygenCmd struct {
	fs     *flag.FlagSet
	keyDir string
}

func NewKeygenCmd() *KeygenCmd {
	c := &KeygenCmd{fs: flag.NewFlagSet("keygen", flag.ContinueOnError)}
	c.fs.StringVar(&c.keyDir, "keydir", "", "directory to save keys (default: ~/.bindboss/keys/)")
	return c
}

func (c *KeygenCmd) Name() string { return "keygen" }
func (c *KeygenCmd) Usage() string {
	return `keygen <name> [flags]

  Generate an Ed25519 keypair for signing packed binaries.
  Saves <name>.key (private) and <name>.pub (public) to the key directory.

  Examples:
    bindboss keygen myproject
    bindboss keygen myproject --keydir=/path/to/keys

  Flags:`
}

func (c *KeygenCmd) Run(args []string) error {
	// GRUG: separate positionals from flags. name is positional.
	var positionals, flagArgs []string
	for _, a := range args {
		if len(a) > 0 && a[0] == '-' {
			flagArgs = append(flagArgs, a)
		} else {
			positionals = append(positionals, a)
		}
	}
	if err := c.fs.Parse(flagArgs); err != nil {
		return err
	}

	if len(positionals) < 1 {
		c.fs.Usage()
		return fmt.Errorf("!!! FATAL: keygen requires a <name> argument")
	}
	name := positionals[0]

	keyDir := c.keyDir
	if keyDir == "" {
		// GRUG: no --keydir = use default ~/.bindboss/keys/. created if missing.
		var err error
		keyDir, err = keys.DefaultKeyDir()
		if err != nil {
			return err
		}
	}

	kp, err := keys.Generate(keyDir, name)
	if err != nil {
		return err
	}

	fmt.Printf("[bindboss] ✓ keypair generated: %s\n", name)
	fmt.Printf("[bindboss]   private key: %s\n", kp.PrivPath)
	fmt.Printf("[bindboss]   public key:  %s\n", kp.PubPath)
	// GRUG: loud warning about the private key. this matters. people lose keys.
	fmt.Fprintf(os.Stderr,
		"[bindboss] IMPORTANT: keep %s secret — it signs your binaries\n", kp.PrivPath)

	return nil
}