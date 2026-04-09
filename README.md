# bindboss

Pack any directory into a single self-extracting executable — with dependency checking, integrity hashing, optional signing, pre/post hooks, and a clean Go library API.

```
bindboss pack ./myapp myapp-bin --run="julia main.jl" --needs="julia,julia --version,https://julialang.org/downloads/"
```

That's it. One binary. Runs anywhere the target platform supports.

---

## Why

Compiling Julia is slow and painful. Bundling Bun the official way is verbose and fragile. You shouldn't need a PhD to ship a directory as an executable. bindboss does one thing: take a directory, a run command, and optional dependency metadata — and produce a single portable binary that handles everything on first run.

---

## Install

```sh
go install github.com/marshalldavidson61-arch/bindboss@latest
```

Or clone and build from source (requires Go 1.23+):

```sh
git clone https://github.com/marshalldavidson61-arch/Bindboss
cd Bindboss
go build -o bindboss .
```

---

## Commands

### `bindboss pack <directory> <output> [flags]`

Pack a directory into a self-extracting binary.

```sh
bindboss pack ./myapp myapp --run="python main.py"
bindboss pack ./grugbot grugbot \
    --run="julia main.jl" \
    --needs="julia,julia --version,https://julialang.org/downloads/"
bindboss pack ./webapp webapp \
    --run="bun run index.ts" \
    --needs="bun,bun --version,https://bun.sh" \
    --persist
bindboss pack ./app app --run="./app" --sign=~/.bindboss/keys/mykey.key
```

Flags:

| Flag | Description |
|------|-------------|
| `--run="cmd"` | Command to run inside the extracted directory (required unless in bindboss.toml) |
| `--needs="name,checkCmd,url"` | Dependency to check on first run. Repeatable. |
| `--persist` | Extract to a fixed directory and reuse on subsequent runs |
| `--dir="path"` | Override extract root directory |
| `--target="GOOS/GOARCH"` | Cross-compile target (e.g. `linux/amd64`, `darwin/arm64`) |
| `--sign="path/to/key.key"` | Sign the payload with an Ed25519 private key |

### `bindboss inspect <binary> [--list]`

Print the embedded configuration, hash, and signature status of a packed binary.

```sh
bindboss inspect ./myapp
bindboss inspect ./myapp --list    # also list all packed files
```

Output includes: run command, exec_mode, format version, SHA-256 hash, signed status, deps, hooks.

### `bindboss verify <binary> [--pubkey=path]`

Verify the payload hash and optionally the Ed25519 signature.

```sh
bindboss verify ./myapp
bindboss verify ./myapp --pubkey=~/.bindboss/keys/mykey.pub
```

Returns exit 0 on success, exit 1 + FATAL message on any failure.

### `bindboss keygen <name> [--keydir=path]`

Generate an Ed25519 keypair for payload signing.

```sh
bindboss keygen myproject
bindboss keygen myproject --keydir=/path/to/keys
```

Creates `<name>.key` (private, mode 0600) and `<name>.pub` (public) in `~/.bindboss/keys/` by default.

### `bindboss reset <name>`

Delete the first-run state for a binary, triggering dep re-check on next run.

```sh
bindboss reset myapp
```

---

## `bindboss.toml` — Config File

Place a `bindboss.toml` in your source directory. CLI flags always override it.

```toml
name = "myapp"
run  = "julia main.jl"
exec_mode = "exec"   # "exec" (default) or "fork" — see below

env = [
    "MY_VAR=hello",
    "OTHER=world",
]

[[needs]]
name    = "julia"
check   = "julia --version"
url     = "https://julialang.org/downloads/"
message = "Install Julia 1.9+ and restart your terminal"

[extract]
persist = false
cleanup = true
dir     = ""

[hooks]
pre_run  = ["sh -c 'echo starting up'", "chmod 755 setup.sh && ./setup.sh"]
post_run = ["sh -c 'echo done'"]  # only fires with exec_mode = "fork" on Unix
```

### `exec_mode`

| Value | Behavior |
|-------|----------|
| `"exec"` (default) | Unix `syscall.Exec` — replaces the stub process entirely. Same PID, clean signal handling, no wrapper. **post_run hooks cannot fire.** |
| `"fork"` | `os/exec.Cmd.Run()` — stub stays alive. post_run hooks fire. Cleanup runs. Costs a wrapper process. |

Windows always uses the fork path.

### `--needs` flag format

```
"name,checkCmd,url"
"name,checkCmd,url,optional message"
```

The check command's **exit code** determines presence — `0` = found, non-zero = missing. No version parsing.

On first run, if a dep is missing: open the URL in the browser, print the message, and wait for the user to press Enter. Re-check. Repeat until all deps are found. State is saved to `~/.bindboss/<name>.state` so the check only happens once.

---

## Integrity: Hash + Signature

Every packed binary (v2 format) includes a SHA-256 hash of the payload bytes in the trailer. This enables:

- **Tamper detection**: `bindboss verify` re-computes the hash from disk and compares it
- **Corruption detection**: bit-flipped payloads are caught before extraction
- **Runtime verification**: set `BINDBOSS_VERIFY=1` before running to verify hash on every exec

Optional Ed25519 signing:

```sh
bindboss keygen myproject                    # generate keypair once
bindboss pack ./app app --sign=myproject.key # sign at pack time
bindboss verify ./app --pubkey=myproject.pub # verify anytime
```

The signature is over the SHA-256 hash of the payload (not the raw bytes), stored in the 121-byte v2 trailer.

---

## Hooks

```toml
[hooks]
pre_run  = ["sh -c 'mkdir -p data'", "chmod 755 run.sh"]
post_run = ["sh -c 'rm -rf /tmp/scratch'"]
```

- Hooks run in order. First failure stops execution — no silent partial runs.
- `BINDBOSS_EXTRACT_DIR` and `BINDBOSS_BINARY_NAME` are injected into hook env.
- No shell expansion — use `sh -c '...'` if you need shell features.
- `post_run` only fires on Windows or when `exec_mode = "fork"`.

---

## Library API

Use bindboss programmatically in your Go projects:

```go
import bb "github.com/marshalldavidson61-arch/bindboss/pkg/bindboss"

// Pack a directory
err := bb.Pack(bb.PackOptions{
    SrcDir:  "./myapp",
    OutPath: "./myapp-bin",
    Run:     "julia main.jl",
    Needs: []bb.Dep{{
        Name:  "julia",
        Check: "julia --version",
        URL:   "https://julialang.org/downloads/",
    }},
})

// Inspect a packed binary
info, err := bb.Inspect("./myapp-bin")
fmt.Println(info.Run, info.Hash, info.SigPresent)

// Verify hash (and optionally signature)
err = bb.Verify("./myapp-bin", nil)             // hash only
err = bb.Verify("./myapp-bin", pubKey)          // hash + sig

// Generate a keypair
priv, pub, err := bb.GenerateKey("", "myproject")

// Load keys
priv, err = bb.LoadPrivateKey("myproject.key")
pub,  err = bb.LoadPublicKey("myproject.pub")

// Pack with signing
err = bb.Pack(bb.PackOptions{
    SrcDir:  "./myapp",
    OutPath: "./myapp-bin",
    Run:     "julia main.jl",
    PrivKey: priv,
})
```

---

## Binary Format

```
[stub ELF/Mach-O/PE]  ← valid executable, OS loads normally
[tar.gz payload]       ← the packed directory
[8b: payload offset]   ← big-endian uint64, where tar.gz starts
[32b: SHA-256 hash]    ← hash of tar.gz bytes
[64b: Ed25519 sig]     ← signature over hash, or zeros if unsigned
[1b: flags]            ← bit 0: hash present, bit 1: sig present
[16b: magic v2]        ← 0xBD055B0B1CEB055C...
```

Total trailer: 121 bytes. Located by seeking to `EOF - 121`.

Legacy v1 format (24-byte trailer, no hash/sig) is detected and read transparently. New stubs warn and run anyway; new binaries always write v2.

---

## Install Wizard (GUI)

bindboss supports a JSON-driven install wizard that replaces the basic "open browser, wait for Enter" dependency check with a guided multi-step installer experience.

### Quick Start

1. Create an `install.json` in your project directory:

```json
{
  "title": "My App",
  "version": "1.0",
  "steps": [
    {
      "type": "welcome",
      "title": "Welcome",
      "content": "Welcome to My App! This wizard will install dependencies."
    },
    {
      "type": "deps",
      "title": "Dependencies",
      "deps": [
        {
          "name": "Julia 1.9+",
          "check": "julia --version",
          "download_url": "https://julialang-s3.julialang.org/bin/linux/x64/1.10/julia-1.10.2-linux-x86_64.tar.gz",
          "fallback_url": "https://julialang.org/downloads/",
          "message": "Julia is required to run this application."
        }
      ]
    },
    {
      "type": "finish",
      "title": "Done",
      "content": "All dependencies installed! The app will start now."
    }
  ]
}
```

2. Enable the wizard in `bindboss.toml`:

```toml
[install]
enabled = true
install_file = "install.json"
```

3. Pack as usual:

```sh
bindboss pack ./myapp myapp --run="julia main.jl"
```

On first run, the packed binary launches the install wizard instead of the basic dep check.

### Step Types

| Type | Description |
|------|-------------|
| `welcome` | Show a greeting message. User presses Enter to continue. |
| `license` | Show license text. User must type "accept" to proceed. |
| `deps` | Check dependencies, download and install missing ones via HTTP. |
| `message` | Show informational text. User presses Enter to continue. |
| `finish` | Show completion message. Wizard exits. |

### Dep Definition Fields

| Field | Required | Description |
|-------|----------|-------------|
| `name` | yes | Human-readable name (e.g. "Julia 1.9+") |
| `check` | yes | Command to test presence — exit 0 = installed |
| `download_url` | * | Direct HTTP(S) download link for the installer |
| `fallback_url` | * | Browser URL if download fails or is unavailable |
| `file_name` | no | Override the downloaded filename |
| `hash` | no | Expected SHA-256 hex digest for verification |
| `message` | no | Extra context shown to the user |

\* At least one of `download_url` or `fallback_url` is required.

### Download Behavior

The install wizard downloads dependency installers directly via HTTP sockets — **no browser is opened**. The flow for each missing dependency:

1. HTTP GET the download URL with progress bar
2. Optionally verify SHA-256 hash of downloaded file
3. Launch the downloaded installer (platform-aware: .exe, .msi, .dmg, .sh, etc.)
4. Wait for user to confirm installation is complete
5. Re-check the dependency with the check command
6. Retry if still not found

### Navigation

- **Enter** — proceed to next step
- **"back" + Enter** — go back one step
- **"retry" + Enter** — re-download a failed dependency
- **Ctrl+C** — abort the wizard entirely

### Inline vs File Config

The install wizard JSON can be provided two ways in `bindboss.toml`:

```toml
# Option 1: Reference a JSON file in the packed directory
[install]
enabled = true
install_file = "install.json"

# Option 2: Inline the JSON directly (useful for small configs)
[install]
enabled = true
install_config = '{"title":"My App","steps":[...]}'
```

If both are set, `install_config` (inline) takes priority.

### Backward Compatibility

If no `[install]` section is present in `bindboss.toml` (or `enabled = false`), the stub falls back to the original dep check behavior: check command → open browser → wait for Enter → re-check. Existing binaries are unaffected.

---

## Design Philosophy

- **Error-first**: every failure path returns a descriptive `!!! FATAL:` error. Nothing silent.
- **No runtime deps**: packed binaries are statically compiled. No libc, no framework.
- **One command**: `bindboss pack dir out --run="cmd"` is the entire workflow.
- **Integrity by default**: hash is always computed and stored. You don't opt in to knowing if your binary is intact.
- **Grug-style internals**: simple data structures, no clever abstractions, comments explain why not just what.