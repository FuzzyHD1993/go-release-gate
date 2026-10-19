package checks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const goCommandTimeout = 5 * time.Minute

// DefaultSandboxImage is the container image used for safe go test execution.
const DefaultSandboxImage = "golang:1.27-alpine"

// BasicOptions controls the basic checks.
type BasicOptions struct {
	// SandboxImage overrides the container image used for go test.
	// Empty means DefaultSandboxImage.
	SandboxImage string
}

// CheckResult describes one command executed as part of the basic checks.
type CheckResult struct {
	Module   string
	Command  string
	Success  bool
	Output   string
	Duration time.Duration
}

// BasicCheckError reports one or more failed go build/vet/test commands.
type BasicCheckError struct {
	Failures []CheckResult
}

func (e *BasicCheckError) Error() string {
	if len(e.Failures) == 1 {
		return fmt.Sprintf("1 basic check failed (%s in %s)", e.Failures[0].Command, e.Failures[0].Module)
	}
	return fmt.Sprintf("%d basic checks failed", len(e.Failures))
}

var errNoGoModules = errors.New("no go.mod files found")

var skippedDirNames = map[string]bool{
	"vendor":   true,
	"testdata": true,
}

// shouldSkipDir follows the Go tool's tree rules: vendor and testdata are
// special, and directories starting with "." or "_" are ignored. Other
// directories (build, bin, dist, node_modules) may still contain compiled Go
// packages, so they are not skipped.
func shouldSkipDir(name string) bool {
	return strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") || skippedDirNames[name]
}

// FindModules returns every directory containing a go.mod below root.
// It does not follow symlinks and skips vendor, testdata and common build dirs.
func FindModules(root string) ([]string, error) {
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, fmt.Errorf("resolve project root: %w", err)
	}
	root = resolved
	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("stat project root: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("project root %s is not a directory", root)
	}

	var modules []string
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if path != root && shouldSkipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			// Follow only symlinks that resolve to a regular file inside the
			// project. Broken/out-of-root links are ignored.
			_, _, ok, _ := resolveWithinRoot(root, path)
			if ok && d.Name() == "go.mod" {
				modules = append(modules, filepath.Dir(path))
			}
			return nil
		}
		if d.Name() == "go.mod" {
			modules = append(modules, filepath.Dir(path))
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk project: %w", err)
	}
	if len(modules) == 0 {
		return nil, fmt.Errorf("%w under %s", errNoGoModules, root)
	}

	sort.Strings(modules)
	return modules, nil
}

// RunBasicChecks runs go build, go vet and sandboxed go test in every module
// below root. It uses the default sandbox image.
func RunBasicChecks(ctx context.Context, root string) ([]CheckResult, error) {
	return RunBasicChecksWithOptions(ctx, root, BasicOptions{})
}

// RunBasicChecksWithOptions runs go build, go vet and a Podman-sandboxed go
// test in every module below root. It keeps checking after a failure so all
// problems are reported at once.
func RunBasicChecksWithOptions(ctx context.Context, root string, opts BasicOptions) ([]CheckResult, error) {
	if opts.SandboxImage == "" {
		opts.SandboxImage = DefaultSandboxImage
	}

	podman, err := exec.LookPath("podman")
	if err != nil {
		return nil, errors.New("Podman required for safe testing")
	}
	podman, err = filepath.Abs(podman)
	if err != nil {
		return nil, fmt.Errorf("resolve podman executable: %w", err)
	}

	modules, err := FindModules(root)
	if err != nil {
		return nil, err
	}

	var results []CheckResult
	var failures []CheckResult

	for _, module := range modules {
		if err := ctx.Err(); err != nil {
			return results, err
		}
		hasGo, err := containsGoFiles(module)
		if err != nil {
			return results, fmt.Errorf("inspect module %s: %w", module, err)
		}
		if !hasGo {
			results = append(results, CheckResult{
				Module:  module,
				Command: "skip (no Go files)",
				Success: true,
			})
			continue
		}

		for _, command := range []string{"build", "vet", "test"} {
			var result CheckResult
			if command == "test" {
				result = runPodmanTest(ctx, podman, root, module, opts.SandboxImage)
			} else {
				result = runGoCommand(ctx, module, command)
			}
			results = append(results, result)
			if !result.Success {
				failures = append(failures, result)
			}
		}
	}

	if len(failures) > 0 {
		return results, &BasicCheckError{Failures: failures}
	}
	return results, nil
}

func containsGoFiles(dir string) (bool, error) {
	found := false
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if path != dir && shouldSkipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			_, _, ok, _ := resolveWithinRoot(dir, path)
			if ok && strings.HasSuffix(d.Name(), ".go") {
				found = true
				return filepath.SkipAll
			}
			return nil
		}
		if strings.HasSuffix(d.Name(), ".go") {
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	return found, nil
}

func runGoCommand(parent context.Context, module, command string) CheckResult {
	modFlag := "-mod=readonly"
	if _, err := os.Stat(filepath.Join(module, "vendor", "modules.txt")); err == nil {
		// Preserve Go's default vendor mode instead of forcing module downloads.
		modFlag = "-mod=vendor"
	}
	args := []string{command, modFlag}
	result := CheckResult{Module: module, Command: "go " + strings.Join(args, " ")}
	start := time.Now()

	ctx, cancel := context.WithTimeout(parent, goCommandTimeout)
	defer cancel()

	goBin, err := exec.LookPath("go")
	if err != nil {
		result.Duration = time.Since(start)
		result.Output = "go executable not found in PATH"
		return result
	}
	goBin, err = filepath.Abs(goBin)
	if err != nil {
		result.Duration = time.Since(start)
		result.Output = fmt.Sprintf("resolve go executable: %v", err)
		return result
	}

	if command == "build" {
		mainPackages, err := hasMainPackages(ctx, goBin, module, modFlag)
		if err != nil {
			result.Duration = time.Since(start)
			result.Output = err.Error()
			return result
		}
		if mainPackages {
			// Write compiled binaries outside the audited tree.
			dir, err := os.MkdirTemp("", "gorelease-build-")
			if err != nil {
				result.Duration = time.Since(start)
				result.Output = fmt.Sprintf("create build output directory: %v", err)
				return result
			}
			defer os.RemoveAll(dir)
			args = append(args, "-o", dir+string(os.PathSeparator))
		}
	}
	args = append(args, "./...")
	result.Command = "go " + strings.Join(args, " ")

	cmd := exec.CommandContext(ctx, goBin, args...)
	cmd.Dir = module
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local")

	var stdout, stderr limitedBuffer
	stdout.max = maxAgentOutput
	stderr.max = maxAgentOutput
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	configureProcessGroup(cmd)

	runErr := cmd.Run()
	result.Duration = time.Since(start)
	result.Output = sanitizeTerminal(strings.TrimRight(joinOutput(stdout.String(), stderr.String()), "\n"))
	if stdout.truncated || stderr.truncated {
		result.Output = joinOutput(result.Output, fmt.Sprintf("[output truncated at %d bytes]", maxAgentOutput))
	}

	if runErr == nil {
		result.Success = true
		// Successful output is not printed, so do not retain it in memory.
		result.Output = ""
		return result
	}

	result.Success = false
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		result.Output = joinOutput(result.Output, fmt.Sprintf("command timed out after %s", goCommandTimeout))
	} else {
		result.Output = joinOutput(result.Output, runErr.Error())
	}
	return result
}

func hasMainPackages(parent context.Context, goBin, module, modFlag string) (bool, error) {
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, goBin, "list", modFlag, "-f", `{{if eq .Name "main"}}{{.ImportPath}}{{end}}`, "./...")
	cmd.Dir = module
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local")

	var stdout, stderr limitedBuffer
	stdout.max = maxAgentOutput
	stderr.max = maxAgentOutput
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	configureProcessGroup(cmd)

	if err := cmd.Run(); err != nil {
		return false, fmt.Errorf("go list main packages: %w: %s", err, strings.TrimSpace(sanitizeTerminal(joinOutput(stdout.String(), stderr.String()))))
	}
	return strings.TrimSpace(stdout.String()) != "", nil
}

func runPodmanTest(parent context.Context, podmanBin, root, module, image string) CheckResult {
	rel, err := filepath.Rel(root, module)
	if err != nil {
		return CheckResult{
			Module:  module,
			Command: "podman run (invalid module path)",
			Output:  fmt.Sprintf("resolve module path relative to project root: %v", err),
		}
	}
	workdir := "/app"
	if rel != "." {
		workdir = "/app/" + filepath.ToSlash(rel)
	}
	args := []string{
		"run", "--rm",
		"--timeout", fmt.Sprintf("%d", int(goCommandTimeout.Seconds())),
		"-v", root + ":/app",
		"-w", workdir,
		image,
		"go", "test", "./...", "-count=1",
	}
	result := CheckResult{
		Module:  module,
		Command: "podman " + strings.Join(args, " "),
	}
	start := time.Now()

	ctx, cancel := context.WithTimeout(parent, goCommandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, podmanBin, args...)
	cmd.Dir = root

	var stdout, stderr limitedBuffer
	stdout.max = maxAgentOutput
	stderr.max = maxAgentOutput
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	configureProcessGroup(cmd)

	runErr := cmd.Run()
	result.Duration = time.Since(start)
	result.Output = sanitizeTerminal(strings.TrimRight(joinOutput(stdout.String(), stderr.String()), "\n"))
	if stdout.truncated || stderr.truncated {
		result.Output = joinOutput(result.Output, fmt.Sprintf("[output truncated at %d bytes]", maxAgentOutput))
	}

	if runErr == nil {
		result.Success = true
		result.Output = ""
		return result
	}

	result.Success = false
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		result.Output = joinOutput(result.Output, fmt.Sprintf("command timed out after %s", goCommandTimeout))
	} else {
		result.Output = joinOutput(result.Output, runErr.Error())
	}
	return result
}

func joinOutput(output, suffix string) string {
	if output == "" {
		return suffix
	}
	return output + "\n" + suffix
}
