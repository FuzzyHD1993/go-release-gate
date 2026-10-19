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

func installFakePodman(t *testing.T, script string) string {
	t.Helper()
	return installFakeCommand(t, "podman", script)
}

func TestRunBasicChecksPassesWithFakeGo(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "go.mod"), "module fixture\n\ngo 1.22\n")
	writeTestFile(t, filepath.Join(root, "main.go"), "package main\n\nfunc main() {}\n")
	installFakeCommand(t, "go", "#!/bin/sh\necho \"fake go $*\"\nexit 0\n")
	installFakePodman(t, "#!/bin/sh\necho \"fake podman $*\"\nexit 0\n")

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
	if !strings.HasPrefix(results[0].Command, "go build -mod=readonly") ||
		!strings.Contains(results[0].Command, "-o ") ||
		results[1].Command != "go vet -mod=readonly ./..." {
		t.Fatalf("unexpected build/vet commands: %+v", results)
	}
	if !strings.HasPrefix(results[2].Command, "podman run --rm") ||
		!strings.Contains(results[2].Command, "golang:1.27-alpine go test ./... -count=1") {
		t.Fatalf("unexpected sandboxed test command: %q", results[2].Command)
	}
}

func TestRunBasicChecksAggregatesFailures(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "go.mod"), "module fixture\n\ngo 1.22\n")
	writeTestFile(t, filepath.Join(root, "main.go"), "package main\n\nfunc main() {}\n")
	installFakeCommand(t, "go", "#!/bin/sh\necho ok\nexit 0\n")
	installFakePodman(t, "#!/bin/sh\necho 'test failed'\nexit 1\n")

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
	if !strings.HasPrefix(basicErr.Failures[0].Command, "podman run --rm") {
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
	bin := installFakePodman(t, "#!/bin/sh\nexit 0\n")
	t.Setenv("PATH", bin)

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

func TestRunBasicChecksRequiresPodman(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "go.mod"), "module fixture\n\ngo 1.22\n")
	writeTestFile(t, filepath.Join(root, "main.go"), "package main\n\nfunc main() {}\n")
	bin := installFakeCommand(t, "go", "#!/bin/sh\nexit 0\n")
	t.Setenv("PATH", bin)

	results, err := RunBasicChecks(context.Background(), root)
	if err == nil || err.Error() != "Podman required for safe testing" {
		t.Fatalf("err = %v, want Podman required for safe testing", err)
	}
	if len(results) != 0 {
		t.Fatalf("got %d results, want 0", len(results))
	}
}

func TestFindModulesSkipsSymlinkGoMod(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "go.mod"), "module root\n\ngo 1.22\n")
	outside := filepath.Join(t.TempDir(), "go.mod")
	writeTestFile(t, outside, "module outside\n")
	if err := os.MkdirAll(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "sub", "go.mod")); err != nil {
		t.Skipf("symlinks are not available: %v", err)
	}
	modules, err := FindModules(root)
	if err != nil {
		t.Fatalf("FindModules: %v", err)
	}
	if len(modules) != 1 || modules[0] != root {
		t.Fatalf("got %v, want only %s", modules, root)
	}
}

func TestRunBasicChecksUsesVendorMode(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "go.mod"), "module fixture\n\ngo 1.22\n")
	writeTestFile(t, filepath.Join(root, "main.go"), "package main\n\nfunc main() {}\n")
	writeTestFile(t, filepath.Join(root, "vendor", "modules.txt"), "# fixture\n")
	goLog := filepath.Join(t.TempDir(), "go-args.log")
	podmanLog := filepath.Join(t.TempDir(), "podman-args.log")
	installFakeCommand(t, "go", "#!/bin/sh\nif [ \"$1\" = \"list\" ]; then echo fixture/main; exit 0; fi\necho \"$*\" >> \"$FAKE_GO_LOG\"\nexit 0\n")
	installFakePodman(t, "#!/bin/sh\necho \"$*\" >> \"$FAKE_PODMAN_LOG\"\nexit 0\n")
	t.Setenv("FAKE_GO_LOG", goLog)
	t.Setenv("FAKE_PODMAN_LOG", podmanLog)

	if _, err := RunBasicChecks(context.Background(), root); err != nil {
		t.Fatalf("RunBasicChecks: %v", err)
	}
	data, err := os.ReadFile(goLog)
	if err != nil {
		t.Fatalf("read fake go log: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d go commands, want 2: %q", len(lines), data)
	}
	for _, line := range lines {
		if !strings.Contains(line, "-mod=vendor") {
			t.Fatalf("command does not use vendor mode: %q", line)
		}
	}
	podmanData, err := os.ReadFile(podmanLog)
	if err != nil {
		t.Fatalf("read fake podman log: %v", err)
	}
	if !strings.Contains(string(podmanData), "golang:1.27-alpine go test ./... -count=1") {
		t.Fatalf("unexpected podman args: %q", podmanData)
	}
}

func TestRunBasicChecksMountsProjectRootForNestedModule(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "sub")
	writeTestFile(t, filepath.Join(root, "go.mod"), "module root\n\ngo 1.22\n")
	writeTestFile(t, filepath.Join(root, "main.go"), "package main\n\nfunc main() {}\n")
	writeTestFile(t, filepath.Join(sub, "go.mod"), "module sub\n\ngo 1.22\n")
	writeTestFile(t, filepath.Join(sub, "main.go"), "package main\n\nfunc main() {}\n")
	installFakeCommand(t, "go", "#!/bin/sh\nif [ \"$1\" = \"list\" ]; then echo fixture/main; exit 0; fi\nexit 0\n")
	podmanLog := filepath.Join(t.TempDir(), "podman-args.log")
	installFakePodman(t, "#!/bin/sh\necho \"$*\" >> \"$FAKE_PODMAN_LOG\"\nexit 0\n")
	t.Setenv("FAKE_PODMAN_LOG", podmanLog)

	if _, err := RunBasicChecks(context.Background(), root); err != nil {
		t.Fatalf("RunBasicChecks: %v", err)
	}
	data, err := os.ReadFile(podmanLog)
	if err != nil {
		t.Fatalf("read fake podman log: %v", err)
	}
	text := string(data)
	if !strings.Contains(text, "-v "+root+":/app") {
		t.Fatalf("podman does not mount project root: %q", text)
	}
	if !strings.Contains(text, "-w /app/sub") {
		t.Fatalf("nested module workdir missing: %q", text)
	}
}

func TestRunBasicChecksSkipsModuleWithoutGoFiles(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "go.mod"), "module fixture\n\ngo 1.22\n")
	installFakePodman(t, "#!/bin/sh\nexit 0\n")

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
