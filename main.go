package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"go-release-gate/checks"
)

const defaultAITimeout = 10 * time.Minute

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 1
	}

	switch args[0] {
	case "check":
		return runCheck(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		usage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n", args[0])
		usage(stderr)
		return 1
	}
}

func runCheck(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("goreleasegate check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { checkUsage(stderr) }

	project := fs.String("project", ".", "path to the Go project to check")
	changedOnly := fs.Bool("changed-only", false, "audit only changed and untracked Go files")
	aiTimeout := fs.Duration("timeout", defaultAITimeout, "per-agent AI audit timeout")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 1
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "unexpected arguments: %v\n\n", fs.Args())
		checkUsage(stderr)
		return 1
	}
	if *aiTimeout <= 0 {
		fmt.Fprintln(stderr, "--timeout must be greater than zero")
		return 1
	}

	root, err := resolveProject(*project)
	if err != nil {
		fmt.Fprintf(stderr, "project: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "Release gate for %s\n\n", root)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Fprintln(stdout, "== Basic checks ==")
	basicResults, basicErr := checks.RunBasicChecks(ctx, root)
	if len(basicResults) == 0 {
		fmt.Fprintln(stdout, "no Go modules were checked")
	}
	for _, result := range basicResults {
		status := "OK"
		if !result.Success {
			status = "FAIL"
		}
		fmt.Fprintf(stdout, "[%s] %s: %s (%s)\n", status, result.Module, result.Command, result.Duration.Round(time.Millisecond))
		if !result.Success && result.Output != "" {
			fmt.Fprintf(stdout, "%s\n", result.Output)
		}
	}
	if basicErr != nil {
		fmt.Fprintf(stdout, "\nbasic checks failed: %v\n", basicErr)
		fmt.Fprintln(stdout, "\nVERDICT: NO-GO")
		return 1
	}

	fmt.Fprintln(stdout, "\n== AI audit ==")
	report, auditErr := checks.RunAIAudit(ctx, root, checks.AuditOptions{
		ChangedOnly:  *changedOnly,
		AgentTimeout: *aiTimeout,
	})
	if report != nil {
		for _, agent := range report.Agents {
			fmt.Fprintf(stdout, "[%s] %s (%s)\n", agent.Verdict, agent.Agent, agent.Reason)
			if agent.LogPath != "" {
				fmt.Fprintf(stdout, "      log: %s\n", agent.LogPath)
			}
		}
		if report.FallbackToAll {
			fmt.Fprintln(stdout, "note: --changed-only found no changes; audited all Go files")
		}
		if report.OmittedFiles > 0 {
			fmt.Fprintf(stdout, "coverage incomplete: %d Go file(s) omitted due to size limits\n", report.OmittedFiles)
		}
		if report.LogDir != "" {
			fmt.Fprintf(stdout, "\nAudit logs: %s\n", report.LogDir)
		}
	}
	if auditErr != nil {
		fmt.Fprintf(stdout, "\nAI audit failed: %v\n", auditErr)
		fmt.Fprintln(stdout, "\nVERDICT: NO-GO")
		return 1
	}
	if report == nil || !report.OverallGO {
		fmt.Fprintln(stdout, "\nVERDICT: NO-GO")
		return 1
	}

	fmt.Fprintln(stdout, "\nVERDICT: GO")
	return 0
}

func resolveProject(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(filepath.Clean(abs))
	if err != nil {
		return "", err
	}

	info, err := os.Stat(resolved)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%s is not a directory", resolved)
	}
	return resolved, nil
}

func usage(w io.Writer) {
	fmt.Fprintln(w, `goreleasegate - release readiness gate for Go projects

Usage:
  goreleasegate check [--project PATH] [--changed-only] [--timeout DURATION]
  goreleasegate help

Commands:
  check    run go build, go vet, go test and a three-agent AI audit
  help     show this help

Exit codes:
  0  all checks passed and every AI agent returned VERDICT: GO
  1  any check failed, any agent returned VERDICT: NO-GO, or an error occurred`)
}

func checkUsage(w io.Writer) {
	fmt.Fprintln(w, `Usage:
  goreleasegate check [--project PATH] [--changed-only] [--timeout DURATION]

Flags:
  --project PATH       project root to check (default ".")
  --changed-only       audit only Go files changed or untracked relative to git HEAD
  --timeout DURATION   per-agent AI audit timeout (default 10m)`)
}
