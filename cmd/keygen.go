// keygen.go
// =============================================================================
// GRUG: The keygen command. Generates an Ed25519 keypair and saves it to
// ~/.bindboss/keys/ so you can sign packed binaries with --sign=<keyfile>.
//
// ACADEMIC: Key generation is a one-time setup operation. The private key
// file (.key) must be kept secret — it signs your binaries. The public key
// file (.pub) can be distributed freely — it verifies signatures.
//
// We use a named key pattern (bindboss keygen myproject) so you can have
// per-project keys without confusion. The name is just a filename, not
// embedded in the key material itself.
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
	fmt.Fprintf(os.Stderr,
		"[bindboss] IMPORTANT: keep %s secret — it signs your binaries\n", kp.PrivPath)

	return nil
}