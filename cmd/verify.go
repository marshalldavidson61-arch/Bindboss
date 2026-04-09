// verify.go
// =============================================================================
// GRUG: The verify command. Checks that a packed binary's payload hash
// matches its stored hash, and optionally verifies its Ed25519 signature.
// If either check fails — FATAL. No "probably fine" output.
//
// ACADEMIC: Two independent integrity checks are available:
//
//  1. Hash verification: re-reads the raw tar.gz bytes from the binary,
//     computes SHA-256, compares against the stored hash in the v2 trailer.
//     Detects corruption and casual tampering. Does not require a key.
//
//  2. Signature verification: checks the Ed25519 signature in the trailer
//     against the payload hash using the provided public key. Detects
//     intentional tampering — an attacker would need the private key to
//     produce a valid signature for a modified payload.
//
// Both checks can run independently. --pubkey is only required for sig check.
// =============================================================================

package cmd

import (
	"flag"
	"fmt"

	"github.com/marshalldavidson61-arch/bindboss/internal/archive"
	"github.com/marshalldavidson61-arch/bindboss/internal/keys"
)

// VerifyCmd implements `bindboss verify`.
type VerifyCmd struct {
	fs     *flag.FlagSet
	pubKey string // path to .pub file for signature verification
}

func NewVerifyCmd() *VerifyCmd {
	c := &VerifyCmd{fs: flag.NewFlagSet("verify", flag.ContinueOnError)}
	c.fs.StringVar(&c.pubKey, "pubkey", "", "path to Ed25519 public key file for signature verification")
	return c
}

func (c *VerifyCmd) Name() string { return "verify" }
func (c *VerifyCmd) Usage() string {
	return `verify <binary> [flags]

  Verify the integrity of a packed binary.
  Always checks the payload hash. Also verifies the Ed25519 signature
  if --pubkey is provided.

  Examples:
    bindboss verify ./myapp
    bindboss verify ./myapp --pubkey=~/.bindboss/keys/myproject.pub

  Flags:`
}

func (c *VerifyCmd) Run(args []string) error {
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
		return fmt.Errorf("!!! FATAL: verify requires a <binary> argument")
	}
	binPath := positionals[0]

	// ------------------------------------------------------------------
	// Step 1: Hash verification (always)
	// ------------------------------------------------------------------
	fmt.Printf("[bindboss] verifying payload hash: %s\n", binPath)
	if err := archive.VerifyHash(binPath); err != nil {
		return err
	}

	// Print the stored hash for reference
	info, err := archive.FindPayload(binPath)
	if err != nil {
		return err
	}
	info.Reader.Close()
	fmt.Printf("[bindboss] ✓ hash OK: %x\n", info.Hash)

	// ------------------------------------------------------------------
	// Step 2: Signature verification (if --pubkey provided)
	// ------------------------------------------------------------------
	if c.pubKey != "" {
		fmt.Printf("[bindboss] verifying Ed25519 signature with: %s\n", c.pubKey)
		pub, err := keys.LoadPublicKey(c.pubKey)
		if err != nil {
			return err
		}
		if err := archive.VerifySig(binPath, pub); err != nil {
			return err
		}
		fmt.Printf("[bindboss] ✓ signature OK\n")
	} else {
		if info.SigPresent {
			fmt.Printf("[bindboss]   note: binary is signed — use --pubkey to verify signature\n")
		} else {
			fmt.Printf("[bindboss]   note: binary is unsigned (packed without --sign)\n")
		}
	}

	fmt.Printf("[bindboss] ✓ %s is intact\n", binPath)
	return nil
}