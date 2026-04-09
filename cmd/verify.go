// verify.go
// =============================================================================
// GRUG: The verify command. Grug want to know: is this binary intact?
// Did someone tamper with it? Did the download corrupt it?
// `bindboss verify ./myapp` answers. Pass = intact. Fail = !!! FATAL.
// No "probably fine". No warnings. No partial passes. Binary or nothing.
//
// Two checks, both optional independently:
//   1. Hash check (always runs): recompute SHA-256 of payload, compare to
//      stored hash in v2 trailer. Catches corruption and casual tampering.
//      Does not require any key.
//   2. Sig check (--pubkey=<file>): verify Ed25519 signature in trailer
//      against the payload hash using the public key. Catches intentional
//      tampering by anyone who does not have the private key.
//
// v1 binaries have no trailer hash. Grug cannot verify them.
// Solution: repack with current bindboss. v2 trailers always include hash.
//
// ---
// ACADEMIC: Two independent integrity invariants are checked in sequence:
//
//   Invariant 1 — Payload hash integrity:
//     archive.VerifyHash re-reads the raw tar.gz bytes from the binary
//     (using the tar_offset stored in the v2 trailer), computes SHA-256,
//     and compares against the 32-byte hash stored in the trailer.
//     This detects single-bit corruption, truncation, and casual byte-flips.
//     SHA-256 provides 128-bit preimage resistance — finding a modified
//     payload that produces the same hash requires ~2^128 hash evaluations,
//     which is computationally infeasible.
//
//   Invariant 2 — Ed25519 signature validity (optional):
//     archive.VerifySig calls ed25519.Verify(pubKey, SHA-256(payload), sig)
//     where sig is the 64-byte value stored in the v2 trailer.
//     Ed25519 verification is deterministic and constant-time in the Go
//     standard library. A valid signature proves the payload was signed by
//     the holder of the corresponding private key at pack time — an attacker
//     who modifies the payload cannot produce a valid signature without the
//     private key (Ed25519 EUF-CMA security).
//
//   The two checks are independent: a binary can pass hash check and fail
//   sig check (e.g., binary was packed without --sign, then someone adds a
//   fake zero signature). Running both provides defense in depth.
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
	// GRUG: separate positionals from flags. binary path is positional.
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
	// GRUG: no hash = v1 binary. cannot verify. tell user to repack.
	// ------------------------------------------------------------------
	fmt.Printf("[bindboss] verifying payload hash: %s\n", binPath)
	if err := archive.VerifyHash(binPath); err != nil {
		return err
	}

	// GRUG: print the actual hash so user can compare against a known-good value.
	info, err := archive.FindPayload(binPath)
	if err != nil {
		return err
	}
	info.Reader.Close()
	fmt.Printf("[bindboss] ✓ hash OK: %x\n", info.Hash)

	// ------------------------------------------------------------------
	// Step 2: Signature verification (--pubkey only)
	// ------------------------------------------------------------------
	if c.pubKey != "" {
		fmt.Printf("[bindboss] verifying Ed25519 signature with: %s\n", c.pubKey)
		pub, err := keys.LoadPublicKey(c.pubKey)
		if err != nil {
			return err
		}
		if err := archive.VerifySig(binPath, pub); err != nil {
			// GRUG: sig bad = !!! FATAL. not a warning. not "probably fine".
			return err
		}
		fmt.Printf("[bindboss] ✓ signature OK\n")
	} else {
		// GRUG: no --pubkey = just note whether binary is signed or not.
		// user may not have the .pub file handy. not an error.
		if info.SigPresent {
			fmt.Printf("[bindboss]   note: binary is signed — use --pubkey to verify signature\n")
		} else {
			fmt.Printf("[bindboss]   note: binary is unsigned (packed without --sign)\n")
		}
	}

	fmt.Printf("[bindboss] ✓ %s is intact\n", binPath)
	return nil
}