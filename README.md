# bindboss

**Pack a directory into a single executable binary. Ship it anywhere. One command.**

```
bindboss pack ./myapp myapp --run="julia main.jl"
```

That's it. `myapp` is now a self-contained binary that extracts itself and runs on any machine — no install instructions, no "make sure you have X installed first", no Docker.

---

## What it does

`bindboss` appends your entire project directory to a compiled stub binary as a compressed archive. When the output binary runs:

1. Extracts the directory to a temp location
2. On **first run only**: checks for required runtimes. If missing, opens the download URL and waits for you to install before continuing
3. Runs your command from inside the extracted directory
4. Cleans up on exit

The dep check only happens once. State is saved to `~/.bindboss/<name>.state`. Subsequent runs skip straight to execution.

---

## Install

```sh
git clone https://github.com/marshalldavidson61-arch/bindboss
cd bindboss
go build -o bindboss .
# put bindboss on your PATH
```

Or with `go install` (requires Go 1.23+):

```sh
go install github.com/marshalldavidson61-arch/bindboss@latest
```

---

## Commands

### `bindboss pack <directory> <output> [flags]`

Pack a directory into a self-extracting binary.

```sh
# Basic — no dep check
bindboss pack ./myapp myapp --run="python main.py"

# With a required runtime
bindboss pack ./grugbot grugbot \
  --run="julia main.jl" \
  --needs="julia,julia --version,https://julialang.org/downloads/"

# Multiple deps
bindboss pack ./webapp webapp \
  --run="bun run index.ts" \
  --needs="bun,bun --version,https://bun.sh" \
  --needs="git,git --version,https://git-scm.com/downloads"

# Cross-compile for Linux ARM
bindboss pack ./myapp myapp-arm --run="./myapp" --target=linux/arm64

# Keep extracted dir between runs (faster for large runtimes like Julia)
bindboss pack ./grugbot grugbot --run="julia main.jl" --persist
```

**Flags:**

| Flag | Description |
|------|-------------|
| `--run="cmd"` | Command to run inside the extracted directory |
| `--needs="name,checkCmd,url"` | Runtime dep to check on first run. Repeatable. |
| `--needs="name,checkCmd,url,message"` | Same with an optional note shown to the user |
| `--persist` | Extract once to `~/.bindboss/<name>/`, reuse on subsequent runs |
| `--target=GOOS/GOARCH` | Cross-compile target (e.g. `linux/amd64`, `darwin/arm64`) |
| `--dir="/path"` | Override extract directory |

---

### `bindboss inspect <binary> [--list]`

Print the config embedded in a packed binary.

```sh
bindboss inspect ./grugbot
bindboss inspect ./grugbot --list   # also list all packed files
```

---

### `bindboss reset <name>`

Delete the first-run state so the next run re-checks dependencies.

```sh
bindboss reset grugbot
```

Useful after a fresh OS install, after updating a runtime, or to verify the dep check still works.

---

## Config file: `bindboss.toml`

Drop a `bindboss.toml` in your directory as an alternative to CLI flags. CLI flags always override the config file.

```toml
name = "grugbot"
run  = "julia main.jl"
env  = ["JULIA_NUM_THREADS=auto", "JULIA_DEPOT_PATH=.julia"]

[[needs]]
name    = "julia"
check   = "julia --version"
url     = "https://julialang.org/downloads/"
message = "Julia 1.9+ required"

[[needs]]
name  = "git"
check = "git --version"
url   = "https://git-scm.com/downloads"

[extract]
persist = false   # true = reuse extracted dir between runs
cleanup = true    # remove tmpdir on exit (ignored when persist=true)
```

---

## First-run dep check

When a dep is missing, the user sees:

```
[bindboss] first run — checking dependencies...
[bindboss] dependency missing: julia
[bindboss] Julia 1.9+ required
[bindboss] install URL: https://julialang.org/downloads/
[bindboss] press Enter after installing julia (Ctrl+C to abort)...
> [user installs Julia, presses Enter]
[bindboss] julia found ✓
[bindboss] starting grugbot...
Hello from grugbot!
```

After that, `~/.bindboss/grugbot.state` is written. Future runs go straight to execution — no dep check, no delay.

---

## How it works

```
┌─────────────────────────────────────────────────────┐
│                output binary                        │
│                                                     │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────┐  │
│  │  stub ELF   │  │  tar.gz of   │  │  trailer  │  │
│  │  (runner)   │  │  your dir    │  │  8b+16b   │  │
│  └─────────────┘  └──────────────┘  └───────────┘  │
│                                           ↑         │
│                              magic + payload offset │
└─────────────────────────────────────────────────────┘
```

The OS loads and executes the stub ELF (the loader only reads ELF headers at the front). The stub seeks to the last 24 bytes, finds the magic marker and payload offset, seeks to the tar.gz, extracts it, and execs your run command. The extracted directory becomes the working directory.

On Unix, `syscall.Exec` replaces the stub process entirely with your command — no wrapper overhead, clean signal handling, correct PID.

---

## Design philosophy

- **No silent failures.** Every error is printed with context. Nothing swallowed.
- **No magic runtimes.** `bindboss` itself is a single static Go binary with zero runtime dependencies.
- **No lock-in.** Works for Julia, Python, Bun, Node, Rust, shell scripts, anything.
- **No install ceremony.** The dep check is user-driven, human-readable, and runs exactly once.
- **Cross-platform.** `--target=linux/arm64`, `darwin/amd64`, `windows/amd64`, etc.

---

## Requirements

- Go 1.23+ to build `bindboss` itself
- The packed binary has no requirements — it's statically compiled (CGO_ENABLED=0)

---

## License

MIT