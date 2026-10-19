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
			return fmt.Errorf("symlinks are not allowed in project tree: %s", path)
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

// RunBasicChecks runs go build, go vet and go test in every module below root.
// It keeps checking after a failure so all problems are reported at once.
func RunBasicChecks(ctx context.Context, root string) ([]CheckResult, error) {
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
			result := runGoCommand(ctx, module, command)
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
	if command == "test" {
		args = append(args, "-count=1")
	}
	args = append(args, "./...")

	result := CheckResult{
		Module:  module,
		Command: "go " + strings.Join(args, " "),
	}
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

	cmd := exec.CommandContext(ctx, goBin, args...)
	cmd.Dir = module
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local")

	var output limitedBuffer
	output.max = maxAgentOutput
	cmd.Stdout = &output
	cmd.Stderr = &output
	configureProcessGroup(cmd)

	runErr := cmd.Run()
	result.Duration = time.Since(start)
	result.Output = sanitizeTerminal(strings.TrimRight(output.String(), "\n"))
	if output.truncated {
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

func joinOutput(output, suffix string) string {
	if output == "" {
		return suffix
	}
	return output + "\n" + suffix
}
