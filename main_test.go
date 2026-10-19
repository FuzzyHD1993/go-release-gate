package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--help"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.Contains(stdout.String(), "Usage:") {
		t.Fatalf("help output missing usage: %q", stdout.String())
	}
}

func TestRunCheckHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"check", "--help"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	for _, want := range []string{"--project", "--skip-ai", "--sandbox-image"} {
		if !strings.Contains(stderr.String(), want) {
			t.Fatalf("check help missing %s: %q", want, stderr.String())
		}
	}
}

func TestRunUnknownCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"nope"}, &stdout, &stderr); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "unknown command") {
		t.Fatalf("unexpected stderr: %q", stderr.String())
	}
}

func TestRunMissingProject(t *testing.T) {
	var stdout, stderr bytes.Buffer
	missing := filepath.Join(t.TempDir(), "missing")
	if code := run([]string{"check", "--project", missing}, &stdout, &stderr); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "project:") {
		t.Fatalf("unexpected stderr: %q", stderr.String())
	}
}

func TestRunBasicFailureSkipsAIAudit(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module broken\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\n\nfunc main() { this is not valid Go }\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"check", "--project", root}, &stdout, &stderr); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stdout.String(), "VERDICT: NO-GO") {
		t.Fatalf("missing NO-GO verdict: %q", stdout.String())
	}
	if strings.Contains(stdout.String(), "== AI audit ==") {
		t.Fatalf("AI audit should be skipped after basic failure: %q", stdout.String())
	}
}
