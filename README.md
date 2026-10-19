# go-release-gate v0.2.0

Release readiness gate for Go projects. It runs the native Go build/vet checks,
sandboxes `go test` in Podman, and runs a three-agent AI review with chunking,
symlink skipping and prompt-injection defenses.

## What it checks

For every `go.mod` found in the target project (nested modules included):

1. `go build ./...` locally
2. `go vet ./...` locally
3. `go test ./... -count=1` inside
   `podman run --rm -v <module>:/app -w /app golang:1.27-alpine`

If any command fails, the gate returns `VERDICT: NO-GO` and does not spend time
on the AI review. Podman is required; without it the gate fails with
`Podman required for safe testing`.

If the basic checks pass, the tool sends the project's Go source to three
[opencode](https://opencode.ai) agents in parallel:

- `deepseek` — vulnerabilities and logic errors
- `glm` — bugs, error handling, resource leaks, concurrency
- `bunny` — security and authorization

Files larger than 200 KiB are split into chunks of at most 1000 lines or
200 KiB. Every chunk is submitted separately with the marker
`Часть X из Y файла <name>`, and a file is `NO-GO` if any part is `NO-GO`.

Each agent must end with the exact final non-empty line `VERDICT: GO`, without
markdown, backticks, a code fence, or punctuation. Any `VERDICT: NO-GO`, missing
verdict, timeout, non-zero agent exit, truncated stdout, omitted non-regular
file, or failed log write makes the overall verdict `NO-GO`. Symlinks are
skipped instead of aborting the audit.

## Build

```sh
go build -o goreleasegate main.go
```

Requires Go, Podman and `opencode` with the `deepseek`, `glm`, and `bunny`
agents configured. No third-party Go dependencies.

## Usage

```sh
# Full gate
./goreleasegate check --project .

# Another project
./goreleasegate check --project ~/projects/my-service

# Only basic checks (build/vet/sandboxed test), no AI
./goreleasegate check --project . --skip-ai

# Use a different test image
./goreleasegate check --project . --sandbox-image golang:1.27-alpine

# Audit only Go files changed or untracked relative to git HEAD
# (an empty change set falls back to auditing all Go files)
./goreleasegate check --project . --changed-only

# Per-agent AI timeout (default 10m)
./goreleasegate check --project . --timeout 15m
```

Exit code `0` means every basic check passed and all AI prompt units returned
`VERDICT: GO` (or only basic checks were requested with `--skip-ai`). Exit code
`1` means the gate failed or an operational error occurred. The final stdout
line is always `VERDICT: GO` or `VERDICT: NO-GO`.

## Logs

Every AI audit creates a private directory:

```text
/tmp/release-audit-<timestamp>-<random>/
  prompt-000.txt
  prompt-001.txt
  deepseek/000.log
  glm/000.log
  bunny/000.log
  summary.txt
```

The directory is mode `0700`; files are mode `0600`. Logs and prompt files can
contain source code and model output, so treat them accordingly.

## Security model

- `go test` is executed only inside a Podman container. `go build`/`go vet` stay
  local because they do not execute the project's test code.
- The AI agents receive the source inline, run in per-unit empty working
  directories, and are told to ignore instructions embedded in the code.
  Verdict parsing is fail-closed and accepts only the exact final line.
- AI verdicts are advisory; they do not replace human review or a full security
  pipeline.
- The gate sends source code to the configured AI providers. Do not run it on
  code that must not leave the machine unless your `opencode` configuration is
  local-only.
- Audit logs and prompt files contain source code and are not deleted
  automatically.

## Limitations

- Chunking uses 1000 lines / 200 KiB per chunk; a single enormous file can
  produce many AI calls.
- `vendor` and `testdata` directories are skipped, matching the Go tool's tree
  rules. Other directories (including `build`, `bin`, `dist`, and
  `node_modules`) are walked if they contain Go source.
- Symlinks are skipped, so a project that keeps all Go code behind symlinks has
  nothing to audit.
