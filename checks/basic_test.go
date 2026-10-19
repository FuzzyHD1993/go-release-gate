package checks

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func installFakeCommand(t *testing.T, name, script string) string {
	t.Helper()
	bin := t.TempDir()
	path := filepath.Join(bin, name)
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake %s: %v", name, err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return bin
}

func TestFindModulesSkipsJunkDirectories(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "go.mod"), "module root\n\ngo 1.22\n")
	writeTestFile(t, filepath.Join(root, "sub", "go.mod"), "module sub\n\ngo 1.22\n")

	for _, dir := range []string{"vendor/x", ".git/y", "testdata/z", "node_modules/n", "build/b", "dist/d", "bin/e"} {
		writeTestFile(t, filepath.Join(root, filepath.FromSlash(dir), "go.mod"), "module junk\n")
	}

	got, err := FindModules(root)
	if err != nil {
		t.Fatalf("FindModules: %v", err)
	}
	want := []string{
		root,
		filepath.Join(root, "bin", "e"),
		filepath.Join(root, "build", "b"),
		filepath.Join(root, "dist", "d"),
		filepath.Join(root, "node_modules", "n"),
		filepath.Join(root, "sub"),
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestFindModulesWithoutGoMod(t *testing.T) {
	_, err := FindModules(t.TempDir())
	if !errors.Is(err, errNoGoModules) {
		t.Fatalf("expected errNoGoModules, got %v", err)
	}
}

func TestRunBasicChecksPassesWithFakeGo(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "go.mod"), "module fixture\n\ngo 1.22\n")
	writeTestFile(t, filepath.Join(root, "main.go"), "package main\n\nfunc main() {}\n")
	installFakeCommand(t, "go", "#!/bin/sh\necho \"fake go $*\"\nexit 0\n")

	results, err := RunBasicChecks(context.Background(), root)
	if err != nil {
		t.Fatalf("RunBasicChecks: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("got %d results, want 3: %+v", len(results), results)
	}
	for _, result := range results {
		if !result.Success {
			t.Fatalf("unexpected failure: %+v", result)
		}
	}
	if results[0].Command != "go build -mod=readonly ./..." ||
		results[1].Command != "go vet -mod=readonly ./..." ||
		results[2].Command != "go test -mod=readonly -count=1 ./..." {
		t.Fatalf("unexpected command order: %+v", results)
	}
}

func TestRunBasicChecksAggregatesFailures(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "go.mod"), "module fixture\n\ngo 1.22\n")
	writeTestFile(t, filepath.Join(root, "main.go"), "package main\n\nfunc main() {}\n")
	installFakeCommand(t, "go", "#!/bin/sh\nif [ \"$1\" = \"test\" ]; then echo 'test failed'; exit 1; fi\necho ok\nexit 0\n")

	results, err := RunBasicChecks(context.Background(), root)
	if err == nil {
		t.Fatal("expected an error")
	}
	var basicErr *BasicCheckError
	if !errors.As(err, &basicErr) {
		t.Fatalf("expected BasicCheckError, got %T: %v", err, err)
	}
	if len(basicErr.Failures) != 1 {
		t.Fatalf("got %d failures, want 1: %+v", len(basicErr.Failures), basicErr.Failures)
	}
	if basicErr.Failures[0].Command != "go test -mod=readonly -count=1 ./..." {
		t.Fatalf("unexpected failure: %+v", basicErr.Failures[0])
	}
	if !strings.Contains(basicErr.Failures[0].Output, "test failed") {
		t.Fatalf("missing command output: %q", basicErr.Failures[0].Output)
	}
	if len(results) != 3 {
		t.Fatalf("got %d results, want 3", len(results))
	}
}

func TestRunBasicChecksMissingGoBinary(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "go.mod"), "module fixture\n\ngo 1.22\n")
	writeTestFile(t, filepath.Join(root, "main.go"), "package main\n\nfunc main() {}\n")
	t.Setenv("PATH", t.TempDir())

	results, err := RunBasicChecks(context.Background(), root)
	if err == nil {
		t.Fatal("expected an error")
	}
	if len(results) != 3 {
		t.Fatalf("got %d results, want 3", len(results))
	}
	if !strings.Contains(results[0].Output, "not found") {
		t.Fatalf("expected not-found output, got %q", results[0].Output)
	}
}

func TestFindModulesRejectsSymlinkGoMod(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "go.mod"), "module root\n\ngo 1.22\n")
	outside := filepath.Join(t.TempDir(), "go.mod")
	writeTestFile(t, outside, "module outside\n")
	if err := os.Symlink(outside, filepath.Join(root, "sub", "go.mod")); err != nil {
		if err := os.MkdirAll(filepath.Join(root, "sub"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(root, "sub", "go.mod")); err != nil {
			t.Skipf("symlinks are not available: %v", err)
		}
	}
	if _, err := FindModules(root); err == nil {
		t.Fatal("expected a symlink error")
	}
}

func TestRunBasicChecksUsesVendorMode(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "go.mod"), "module fixture\n\ngo 1.22\n")
	writeTestFile(t, filepath.Join(root, "main.go"), "package main\n\nfunc main() {}\n")
	writeTestFile(t, filepath.Join(root, "vendor", "modules.txt"), "# fixture\n")
	logPath := filepath.Join(t.TempDir(), "go-args.log")
	installFakeCommand(t, "go", "#!/bin/sh\necho \"$*\" >> \"$FAKE_GO_LOG\"\nexit 0\n")
	t.Setenv("FAKE_GO_LOG", logPath)

	if _, err := RunBasicChecks(context.Background(), root); err != nil {
		t.Fatalf("RunBasicChecks: %v", err)
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read fake go log: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d commands, want 3: %q", len(lines), data)
	}
	for _, line := range lines {
		if !strings.Contains(line, "-mod=vendor") {
			t.Fatalf("command does not use vendor mode: %q", line)
		}
	}
	if !strings.Contains(lines[2], "-count=1") {
		t.Fatalf("go test does not disable cache: %q", lines[2])
	}
}

func TestRunBasicChecksSkipsModuleWithoutGoFiles(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "go.mod"), "module fixture\n\ngo 1.22\n")

	results, err := RunBasicChecks(context.Background(), root)
	if err != nil {
		t.Fatalf("RunBasicChecks: %v", err)
	}
	if len(results) != 1 || !results[0].Success {
		t.Fatalf("expected one successful skip, got %+v", results)
	}
	if !strings.HasPrefix(results[0].Command, "skip") {
		t.Fatalf("expected skip command, got %q", results[0].Command)
	}
}
