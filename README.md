# go-release-gate

Release readiness gate for Go projects. It runs the native Go toolchain and a
three-agent AI review, then returns a single machine-readable verdict.

## What it checks

For every `go.mod` found in the target project (nested modules included):

1. `go build ./...`
2. `go vet ./...`
3. `go test ./...`

If any command fails, the gate returns `VERDICT: NO-GO` and does not spend time
on the AI review.

If the basic checks pass, the tool sends the project's Go source to three
[opencode](https://opencode.ai) agents in parallel:

- `deepseek` — vulnerabilities and logic errors
- `glm` — bugs, error handling, resource leaks, concurrency
- `bunny` — security and authorization

Each agent must end with the exact final non-empty line `VERDICT: GO`, without
markdown, backticks, a code fence, or punctuation. Any `VERDICT: NO-GO`, missing
verdict, timeout, non-zero agent exit, truncated stdout, omitted source file, or
failed log write makes the overall verdict `NO-GO`.

## Build

```sh
go build -o goreleasegate .
```

Requires Go and `opencode` with the `deepseek`, `glm`, and `bunny` agents
configured. No third-party Go dependencies.

## Usage

```sh
# Check the current project
./goreleasegate check --project .

# Check another project
./goreleasegate check --project ~/projects/my-service

# Audit only Go files changed or untracked relative to git HEAD
# (an empty change set falls back to auditing all Go files)
./goreleasegate check --project . --changed-only

# Per-agent AI timeout (default 10m)
./goreleasegate check --project . --timeout 15m
```

Exit code `0` means every basic check passed and all three agents returned
`VERDICT: GO`. Exit code `1` means the gate failed or an operational error
occurred. The final stdout line is always `VERDICT: GO` or `VERDICT: NO-GO`.

## Logs

Every AI audit creates a private directory:

```text
/tmp/release-audit-<timestamp>-<random>/
  prompt.txt
  deepseek.log
  glm.log
  bunny.log
  summary.txt
```

The directory is mode `0700`; files are mode `0600`. Logs and `prompt.txt` can
contain source code and model output, so treat them accordingly.

## Security warning

The gate is intended for trusted local projects or an isolated CI runner:

- `go test` executes the project's test code, which can read environment
  secrets, use the network, or modify files. Never run it on untrusted code
  outside a sandbox.
- The AI agents run with the configured `opencode` tools. The prompt contains
  the source inline, and the agents are started in an empty working directory so
  repository-local opencode config is not loaded, but model output remains
  untrusted and advisory.
- Audit logs and `prompt.txt` contain source code. They are created with
  `0700`/`0600` permissions under `/tmp` and are not deleted automatically.

## Limitations

- AI verdicts are advisory, not a substitute for human review or a full CI
  security pipeline.
- The prompt tells the models to treat source code as untrusted data, but prompt
  injection cannot be fully prevented. A model can still be wrong or
  inconsistent.
- The gate sends source code to the configured AI providers. Do not run it on
  code that must not leave the machine unless your `opencode` configuration is
  local-only.
- Size limits: files above 256 KiB are omitted, and the prompt payload is capped
  at roughly 512 KiB. Omitted files are reported, and any omission forces the
  overall verdict to `NO-GO` because coverage is incomplete.
- `vendor` and `testdata` directories are skipped, matching the Go tool's tree
  rules. Other directories (including `build`, `bin`, `dist`, and
  `node_modules`) are walked if they contain Go source.
