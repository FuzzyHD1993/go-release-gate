package checks

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	defaultAgentTimeout = 10 * time.Minute
	maxPromptPayload    = 64 * 1024
	maxAgentOutput      = 4 * 1024 * 1024
	maxGitOutput        = 8 * 1024 * 1024
	maxAuditConcurrency = 6

	// VerdictGO and VerdictNoGo are the normalized agent verdicts.
	VerdictGO   = "GO"
	VerdictNoGo = "NO-GO"
)

var auditAgents = [...]string{"deepseek", "glm", "bunny"}

// AuditOptions controls the AI audit.
type AuditOptions struct {
	// ChangedOnly audits only Go files changed or untracked relative to git HEAD.
	// When the change set is empty it falls back to auditing every Go file.
	ChangedOnly bool
	// AgentTimeout is the per-agent timeout. Zero uses the default (10m).
	AgentTimeout time.Duration
}

// AgentResult is the aggregated outcome of one AI reviewer across all prompts.
type AgentResult struct {
	Agent    string
	Prompt   string
	Verdict  string
	Reason   string
	LogPath  string
	Duration time.Duration
	// Err is set for an internal setup failure before the agent produced a verdict.
	Err error
	// LogErr is set when the agent's log could not be written.
	LogErr error
}

// UnitResult is the outcome of one agent reviewing one prompt/chunk.
type UnitResult struct {
	PromptIndex int
	PromptID    string
	Label       string
	Files       []string
	Agent       string
	Verdict     string
	Reason      string
	LogPath     string
	Duration    time.Duration
	Err         error
	LogErr      error
}

// FileVerdict is the aggregated verdict for one source file across chunks.
type FileVerdict struct {
	Path    string
	Verdict string
	Parts   int
	Reasons []string
}

// AuditReport summarizes a multi-prompt, three-agent AI audit.
type AuditReport struct {
	LogDir          string
	PromptPath      string
	PromptPaths     []string
	SummaryPath     string
	PromptSHA256    string
	VerdictNonce    string
	Files           []string
	OmittedFiles    int
	SkippedSymlinks int
	FallbackToAll   bool
	Agents          []AgentResult
	Units           []UnitResult
	FileVerdicts    []FileVerdict
	OverallGO       bool
}

// RunAIAudit sends the project's Go source to three opencode agents. Large
// files are split into chunks; every chunk/agent pair must answer GO.
func RunAIAudit(ctx context.Context, root string, opts AuditOptions) (*AuditReport, error) {
	absRoot, err := resolveProjectRoot(root)
	if err != nil {
		return nil, err
	}
	if opts.AgentTimeout <= 0 {
		opts.AgentTimeout = defaultAgentTimeout
	}

	files, skippedCollect, fallback, err := collectGoFilesForAudit(ctx, absRoot, opts.ChangedOnly)
	if err != nil {
		return nil, err
	}
	// Keep the user-facing verdict format exactly "VERDICT: GO"/"VERDICT: NO-GO".
	// A per-run nonce is available via BuildPromptsWithNonce/ParseVerdictWithNonce
	// for callers that want stronger anti-spoofing, but the CLI uses the simple
	// documented format.
	nonce := ""
	prompts, included, omitted, skippedBuild, err := BuildPromptsWithNonce(absRoot, files, nonce)
	if err != nil {
		return nil, err
	}
	skippedSymlinks := skippedCollect + skippedBuild

	logDir, err := createAuditDir()
	if err != nil {
		return nil, fmt.Errorf("create audit log directory: %w", err)
	}
	runDir := filepath.Join(logDir, "run")
	if err := os.Mkdir(runDir, 0o700); err != nil {
		_ = os.RemoveAll(logDir)
		return nil, fmt.Errorf("create agent working directory: %w", err)
	}

	report := &AuditReport{
		LogDir:          logDir,
		VerdictNonce:    nonce,
		Files:           included,
		OmittedFiles:    omitted,
		SkippedSymlinks: skippedSymlinks,
		FallbackToAll:   fallback,
		Agents:          make([]AgentResult, len(auditAgents)),
		Units:           make([]UnitResult, 0, len(prompts)*len(auditAgents)),
		PromptPaths:     make([]string, 0, len(prompts)),
	}
	report.SummaryPath = filepath.Join(logDir, "summary.txt")

	promptHash := sha256.New()
	for i := range prompts {
		promptPath := filepath.Join(logDir, "prompt-"+prompts[i].ID+".txt")
		if err := os.WriteFile(promptPath, []byte(prompts[i].Text), 0o600); err != nil {
			opErr := fmt.Errorf("write prompt %s: %w", prompts[i].ID, err)
			logErrs := failAll(report, prompts, opts.AgentTimeout, opErr)
			report.OverallGO = false
			if summaryErr := writeSummary(report, absRoot, opts); summaryErr != nil {
				logErrs = append(logErrs, summaryErr)
			}
			return report, errors.Join(append([]error{opErr}, logErrs...)...)
		}
		report.PromptPaths = append(report.PromptPaths, promptPath)
		_, _ = promptHash.Write([]byte(prompts[i].Text))
		_, _ = promptHash.Write([]byte{0})
	}
	report.PromptPath = report.PromptPaths[0]
	report.PromptSHA256 = hex.EncodeToString(promptHash.Sum(nil))

	opencode, lookErr := exec.LookPath("opencode")
	if lookErr != nil {
		opErr := fmt.Errorf("opencode executable not found in PATH: %w", lookErr)
		logErrs := failAll(report, prompts, opts.AgentTimeout, opErr)
		report.OverallGO = false
		if err := writeSummary(report, absRoot, opts); err != nil {
			logErrs = append(logErrs, err)
		}
		return report, errors.Join(append([]error{opErr}, logErrs...)...)
	}
	opencode, err = filepath.Abs(opencode)
	if err != nil {
		opErr := fmt.Errorf("resolve opencode path: %w", err)
		logErrs := failAll(report, prompts, opts.AgentTimeout, opErr)
		report.OverallGO = false
		if err := writeSummary(report, absRoot, opts); err != nil {
			logErrs = append(logErrs, err)
		}
		return report, errors.Join(append([]error{opErr}, logErrs...)...)
	}

	sem := make(chan struct{}, maxAuditConcurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	for pi := range prompts {
		for _, agent := range auditAgents {
			wg.Add(1)
			go func(pi int, agent string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				unit := runAgentUnit(ctx, opencode, runDir, agent, prompts[pi], report.PromptPaths[pi], logDir, nonce, opts.AgentTimeout)
				unit.PromptIndex = pi
				mu.Lock()
				report.Units = append(report.Units, unit)
				mu.Unlock()
			}(pi, agent)
		}
	}
	wg.Wait()

	sort.Slice(report.Units, func(i, j int) bool {
		if report.Units[i].PromptIndex != report.Units[j].PromptIndex {
			return report.Units[i].PromptIndex < report.Units[j].PromptIndex
		}
		return report.Units[i].Agent < report.Units[j].Agent
	})
	aggregateReport(report, prompts)

	var opErrs []error
	for _, agent := range report.Agents {
		if agent.Err != nil {
			opErrs = append(opErrs, agent.Err)
		}
		if agent.LogErr != nil {
			opErrs = append(opErrs, agent.LogErr)
		}
	}
	if err := ctx.Err(); err != nil {
		opErrs = append(opErrs, fmt.Errorf("audit context ended: %w", err))
	}
	if len(opErrs) > 0 {
		report.OverallGO = false
	}
	if err := writeSummary(report, absRoot, opts); err != nil {
		report.OverallGO = false
		opErrs = append(opErrs, err)
	}
	if err := errors.Join(opErrs...); err != nil {
		return report, err
	}
	return report, nil
}

func failAll(report *AuditReport, prompts []AuditPrompt, timeout time.Duration, cause error) []error {
	var logErrs []error
	for pi, prompt := range prompts {
		for _, agent := range auditAgents {
			logPath := filepath.Join(report.LogDir, agent, prompt.ID+".log")
			if err := os.MkdirAll(filepath.Dir(logPath), 0o700); err != nil {
				logErrs = append(logErrs, err)
			}
			logErr := writeAgentLog(logPath, agent, timeout, cause, 0, "", "", false, false)
			if logErr != nil {
				logErrs = append(logErrs, logErr)
			}
			report.Units = append(report.Units, UnitResult{
				PromptIndex: pi,
				PromptID:    prompt.ID,
				Label:       prompt.Label,
				Files:       prompt.Files,
				Agent:       agent,
				Verdict:     VerdictNoGo,
				Reason:      cause.Error(),
				LogPath:     logPath,
				Err:         cause,
				LogErr:      logErr,
			})
		}
	}
	sort.Slice(report.Units, func(i, j int) bool {
		if report.Units[i].PromptIndex != report.Units[j].PromptIndex {
			return report.Units[i].PromptIndex < report.Units[j].PromptIndex
		}
		return report.Units[i].Agent < report.Units[j].Agent
	})
	aggregateReport(report, prompts)
	report.OverallGO = false
	return logErrs
}

func runAgentUnit(ctx context.Context, opencode, runRoot, agent string, prompt AuditPrompt, promptPath, logDir, nonce string, timeout time.Duration) UnitResult {
	start := time.Now()
	result := UnitResult{
		PromptID: prompt.ID,
		Label:    prompt.Label,
		Files:    prompt.Files,
		Agent:    agent,
		Verdict:  VerdictNoGo,
		LogPath:  filepath.Join(logDir, agent, prompt.ID+".log"),
	}

	if err := os.MkdirAll(filepath.Dir(result.LogPath), 0o700); err != nil {
		result.Reason = fmt.Sprintf("create log directory: %v", err)
		result.Err = err
		return result
	}
	agentDir := filepath.Join(runRoot, agent, prompt.ID)
	if err := os.MkdirAll(agentDir, 0o700); err != nil {
		result.Reason = fmt.Sprintf("create agent working directory: %v", err)
		result.Err = err
		result.LogErr = writeAgentLog(result.LogPath, agent, timeout, err, 0, "", "", false, false)
		return result
	}

	promptFile, err := os.Open(promptPath)
	if err != nil {
		result.Reason = fmt.Sprintf("open prompt: %v", err)
		result.Err = err
		result.LogErr = writeAgentLog(result.LogPath, agent, timeout, err, 0, "", "", false, false)
		return result
	}
	defer promptFile.Close()

	agentCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// The prompt is passed on stdin: this avoids ARG_MAX limits and keeps the
	// full source out of the process list. Each agent/unit runs in its own
	// empty directory so a hostile repository cannot inject opencode config.
	cmd := exec.CommandContext(agentCtx, opencode, "run", "--agent", agent)
	cmd.Dir = agentDir
	cmd.Stdin = promptFile

	var stdout, stderr tailBuffer
	stdout.max = maxAgentOutput
	stderr.max = maxAgentOutput
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	configureProcessGroup(cmd)

	runErr := cmd.Run()
	result.Duration = time.Since(start)
	rawStdout := sanitizeTerminal(stdout.String())
	rawStderr := sanitizeTerminal(stderr.String())

	switch {
	case errors.Is(agentCtx.Err(), context.DeadlineExceeded):
		result.Reason = fmt.Sprintf("timed out after %s", timeout)
	case errors.Is(agentCtx.Err(), context.Canceled):
		result.Reason = "canceled"
	case runErr != nil:
		result.Reason = fmt.Sprintf("opencode failed: %v", runErr)
	default:
		verdict, ok := ParseVerdictWithNonce(rawStdout, nonce)
		if !ok {
			result.Reason = "no final VERDICT line found in agent stdout"
			break
		}
		result.Verdict = verdict
		if verdict == VerdictGO {
			result.Reason = "agent returned GO"
		} else {
			result.Reason = "agent returned NO-GO"
		}
	}
	if stdout.truncated {
		result.Reason += fmt.Sprintf(" (stdout head dropped, last %d bytes kept)", maxAgentOutput)
	}
	if stderr.truncated {
		result.Reason += fmt.Sprintf(" (stderr head dropped, last %d bytes kept)", maxAgentOutput)
	}

	if err := writeAgentLog(result.LogPath, agent, timeout, runErr, result.Duration, rawStdout, rawStderr, stdout.truncated, stderr.truncated); err != nil {
		result.LogErr = err
		result.Reason += "; failed to write log: " + err.Error()
	}
	return result
}

func aggregateReport(report *AuditReport, prompts []AuditPrompt) {
	fileParts := make(map[string]int)
	for _, prompt := range prompts {
		for _, file := range prompt.Files {
			if prompt.PrimaryFile == file && prompt.Parts > fileParts[file] {
				fileParts[file] = prompt.Parts
			}
			if fileParts[file] == 0 {
				fileParts[file] = 1
			}
		}
	}

	for i, agent := range auditAgents {
		ar := AgentResult{
			Agent:   agent,
			Verdict: VerdictGO,
			Prompt:  "0 prompt(s)",
			LogPath: filepath.Join(report.LogDir, agent),
		}
		count := 0
		for _, unit := range report.Units {
			if unit.Agent != agent {
				continue
			}
			count++
			ar.Duration += unit.Duration
			if unit.Err != nil {
				ar.Err = errors.Join(ar.Err, unit.Err)
			}
			if unit.LogErr != nil {
				ar.LogErr = errors.Join(ar.LogErr, unit.LogErr)
			}
			if unit.Verdict != VerdictGO {
				ar.Verdict = VerdictNoGo
				if ar.Reason == "" {
					ar.Reason = fmt.Sprintf("%s: %s", unit.Label, unit.Reason)
				}
			}
		}
		ar.Prompt = fmt.Sprintf("%d prompt(s)", count)
		if count == 0 {
			ar.Verdict = VerdictNoGo
			ar.Reason = "no prompts executed"
		} else if ar.Verdict == VerdictGO {
			ar.Reason = fmt.Sprintf("all %d prompt(s) GO", count)
		}
		report.Agents[i] = ar
	}

	fileMap := make(map[string]*FileVerdict)
	for _, unit := range report.Units {
		for _, file := range unit.Files {
			fv := fileMap[file]
			if fv == nil {
				parts := fileParts[file]
				if parts == 0 {
					parts = 1
				}
				fv = &FileVerdict{Path: file, Verdict: VerdictGO, Parts: parts}
				fileMap[file] = fv
			}
			if unit.Verdict != VerdictGO {
				fv.Verdict = VerdictNoGo
				if len(fv.Reasons) < 5 {
					fv.Reasons = append(fv.Reasons, fmt.Sprintf("%s %s: %s", unit.Agent, unit.Label, unit.Reason))
				}
			}
		}
	}
	keys := make([]string, 0, len(fileMap))
	for file := range fileMap {
		keys = append(keys, file)
	}
	sort.Strings(keys)
	report.FileVerdicts = make([]FileVerdict, 0, len(keys))
	for _, file := range keys {
		report.FileVerdicts = append(report.FileVerdicts, *fileMap[file])
	}

	report.OverallGO = len(report.Units) > 0 && len(report.Agents) == len(auditAgents)
	for _, unit := range report.Units {
		if unit.Verdict != VerdictGO {
			report.OverallGO = false
			break
		}
	}
	for _, agent := range report.Agents {
		if agent.Verdict != VerdictGO || agent.Err != nil || agent.LogErr != nil {
			report.OverallGO = false
			break
		}
	}
	if report.OmittedFiles > 0 {
		report.OverallGO = false
	}
}

func writeAgentLog(path, agent string, timeout time.Duration, runErr error, duration time.Duration, stdout, stderr string, stdoutTruncated, stderrTruncated bool) error {
	var b strings.Builder
	fmt.Fprintf(&b, "agent: %s\n", agent)
	fmt.Fprintf(&b, "timeout: %s\n", timeout)
	fmt.Fprintf(&b, "duration: %s\n", duration.Round(time.Millisecond))
	fmt.Fprintf(&b, "exit_error: %v\n", runErr)
	if stdoutTruncated {
		fmt.Fprintln(&b, "stdout_truncated: true")
	}
	if stderrTruncated {
		fmt.Fprintln(&b, "stderr_truncated: true")
	}
	b.WriteString("\n--- stdout ---\n")
	b.WriteString(stdout)
	if stdout != "" && !strings.HasSuffix(stdout, "\n") {
		b.WriteByte('\n')
	}
	b.WriteString("\n--- stderr ---\n")
	b.WriteString(stderr)
	if stderr != "" && !strings.HasSuffix(stderr, "\n") {
		b.WriteByte('\n')
	}
	return os.WriteFile(path, []byte(b.String()), 0o600)
}

func writeSummary(report *AuditReport, root string, opts AuditOptions) error {
	var b strings.Builder
	fmt.Fprintln(&b, "Release Gate AI Audit")
	fmt.Fprintf(&b, "Project: %s\n", root)
	fmt.Fprintf(&b, "Changed-only: %t\n", opts.ChangedOnly)
	fmt.Fprintf(&b, "Fell back to all files: %t\n", report.FallbackToAll)
	fmt.Fprintf(&b, "Prompts: %d\n", len(report.PromptPaths))
	fmt.Fprintf(&b, "Prompt SHA-256: %s\n", report.PromptSHA256)
	if report.VerdictNonce != "" {
		fmt.Fprintf(&b, "Verdict nonce: %s\n", report.VerdictNonce)
	}
	fmt.Fprintf(&b, "Files audited: %d\n", len(report.Files))
	fmt.Fprintf(&b, "Files omitted: %d\n", report.OmittedFiles)
	fmt.Fprintf(&b, "Skipped symlinks: %d\n", report.SkippedSymlinks)
	if report.OmittedFiles > 0 {
		fmt.Fprintln(&b, "Coverage incomplete: omitted files force the overall verdict to NO-GO.")
	}
	fmt.Fprintf(&b, "Log dir: %s\n\n", report.LogDir)

	for _, agent := range report.Agents {
		fmt.Fprintf(&b, "- %s: %s (%s)\n", agent.Agent, agent.Verdict, agent.Prompt)
		fmt.Fprintf(&b, "  reason: %s\n", agent.Reason)
		fmt.Fprintf(&b, "  log dir: %s\n", agent.LogPath)
		if agent.LogErr != nil {
			fmt.Fprintf(&b, "  log error: %v\n", agent.LogErr)
		}
	}

	fmt.Fprintln(&b, "\nPrompt units:")
	for _, unit := range report.Units {
		fmt.Fprintf(&b, "- %s [%s] %s: %s (%s)\n", unit.PromptID, unit.Label, unit.Agent, unit.Verdict, unit.Reason)
	}

	fmt.Fprintln(&b, "\nFile verdicts:")
	for _, fv := range report.FileVerdicts {
		fmt.Fprintf(&b, "- %s: %s (%d part(s))\n", fv.Path, fv.Verdict, fv.Parts)
		for _, reason := range fv.Reasons {
			fmt.Fprintf(&b, "  %s\n", reason)
		}
	}

	overall := VerdictNoGo
	if report.OverallGO {
		overall = VerdictGO
	}
	fmt.Fprintf(&b, "\nVERDICT: %s\n", overall)
	return os.WriteFile(report.SummaryPath, []byte(b.String()), 0o600)
}

func createAuditDir() (string, error) {
	prefix := "release-audit-" + time.Now().Format("20060102-150405") + "-"
	dir, err := os.MkdirTemp(os.TempDir(), prefix)
	if err != nil {
		return "", err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		_ = os.RemoveAll(dir)
		return "", err
	}
	return dir, nil
}

// CollectGoFiles returns Go files below root, either all of them or only those
// changed/untracked relative to git HEAD. An empty change set falls back to all
// Go files so a clean checkout is still audited. Symlinks are skipped.
func CollectGoFiles(root string, changedOnly bool) ([]string, error) {
	absRoot, err := resolveProjectRoot(root)
	if err != nil {
		return nil, err
	}
	files, _, _, err := collectGoFilesForAudit(context.Background(), absRoot, changedOnly)
	return files, err
}

func collectGoFilesForAudit(ctx context.Context, root string, changedOnly bool) ([]string, int, bool, error) {
	if !changedOnly {
		files, skipped, err := collectAllGoFiles(root)
		return files, skipped, false, err
	}
	files, skipped, err := collectChangedGoFiles(ctx, root)
	if err != nil {
		return nil, 0, false, err
	}
	if len(files) == 0 {
		all, allSkipped, err := collectAllGoFiles(root)
		return all, skipped + allSkipped, true, err
	}
	return files, skipped, false, nil
}

func collectAllGoFiles(root string) ([]string, int, error) {
	var files []string
	skipped := 0
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
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
			// Dereference symlinks that stay inside the project; skip broken
			// and out-of-root targets without failing the whole audit.
			_, _, ok, _ := resolveWithinRoot(root, path)
			if !ok {
				if strings.HasSuffix(d.Name(), ".go") {
					skipped++
				}
				return nil
			}
			if strings.HasSuffix(d.Name(), ".go") {
				files = append(files, path)
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if strings.HasSuffix(d.Name(), ".go") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, skipped, fmt.Errorf("walk project: %w", err)
	}
	sort.Strings(files)
	if len(files) == 0 {
		return nil, skipped, errors.New("no Go files found in project")
	}
	return files, skipped, nil
}

func collectChangedGoFiles(ctx context.Context, root string) ([]string, int, error) {
	diffOut, diffErr := runGit(ctx, root, "diff", "--name-only", "-z", "--diff-filter=ACMRT", "--relative", "HEAD", "--", ".")
	if diffErr != nil {
		// An unborn repository has no HEAD; list tracked and untracked files.
		if _, verifyErr := runGit(ctx, root, "rev-parse", "--verify", "HEAD"); verifyErr != nil {
			tracked, trackedErr := runGit(ctx, root, "ls-files", "-z", "--", ".")
			if trackedErr != nil {
				return nil, 0, fmt.Errorf("not a git repository or no HEAD: %v (diff error: %w)", verifyErr, diffErr)
			}
			diffOut = tracked
		} else {
			return nil, 0, diffErr
		}
	}
	// Deliberately include .gitignored untracked files: the Go toolchain still
	// compiles them, so excluding them would create an audit bypass.
	untrackedOut, err := runGit(ctx, root, "ls-files", "--others", "-z", "--", ".")
	if err != nil {
		return nil, 0, err
	}

	seen := make(map[string]bool)
	skipped := 0
	var files []string
	for _, name := range splitNUL(diffOut + "\x00" + untrackedOut) {
		if name == "" || !strings.HasSuffix(name, ".go") {
			continue
		}
		full, err := resolveRepoPath(root, name)
		if err != nil {
			return nil, skipped, err
		}
		if seen[full] || isSkippedRepoPath(root, full) {
			continue
		}
		_, _, ok, resolveErr := resolveWithinRoot(root, full)
		if resolveErr != nil {
			// A changed file can disappear between git and stat; ignore it.
			if errors.Is(resolveErr, fs.ErrNotExist) {
				continue
			}
			return nil, skipped, fmt.Errorf("inspect changed file %s: %w", name, resolveErr)
		}
		if !ok {
			// Symlinks that leave the project (or non-regular entries) are
			// skipped rather than aborting the gate.
			skipped++
			continue
		}
		seen[full] = true
		files = append(files, full)
	}
	sort.Strings(files)
	return files, skipped, nil
}

func splitNUL(s string) []string {
	parts := strings.Split(s, "\x00")
	out := parts[:0]
	for _, part := range parts {
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func runGit(ctx context.Context, root string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	gitBin, err := exec.LookPath("git")
	if err != nil {
		return "", fmt.Errorf("git executable not found in PATH: %w", err)
	}
	gitBin, err = filepath.Abs(gitBin)
	if err != nil {
		return "", fmt.Errorf("resolve git executable: %w", err)
	}

	gitArgs := append([]string{"--no-pager", "-C", root}, args...)
	cmd := exec.CommandContext(ctx, gitBin, gitArgs...)
	var stdout, stderr limitedBuffer
	stdout.max = maxGitOutput
	stderr.max = maxGitOutput
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	configureProcessGroup(cmd)
	runErr := cmd.Run()
	if runErr != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return "", errors.New("git command timed out")
		}
		diagnostics := strings.TrimSpace(sanitizeTerminal(stdout.String() + "\n" + stderr.String()))
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), runErr, diagnostics)
	}
	if stdout.truncated || stderr.truncated {
		return "", fmt.Errorf("git %s output exceeded %d bytes", strings.Join(args, " "), maxGitOutput)
	}
	return stdout.String(), nil
}

func isSkippedRepoPath(root, full string) bool {
	rel, err := filepath.Rel(root, full)
	if err != nil {
		return false
	}
	parts := strings.Split(filepath.ToSlash(rel), "/")
	if len(parts) <= 1 {
		return false
	}
	for _, part := range parts[:len(parts)-1] {
		if shouldSkipDir(part) {
			return true
		}
	}
	return false
}

func resolveRepoPath(root, rel string) (string, error) {
	if rel == "" {
		return "", errors.New("empty repository path")
	}
	if strings.ContainsRune(rel, 0) {
		return "", fmt.Errorf("repository path %q contains a NUL byte", rel)
	}
	if filepath.IsAbs(rel) {
		return "", fmt.Errorf("repository path %q is absolute", rel)
	}
	clean := filepath.Clean(filepath.FromSlash(rel))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("repository path %q escapes project root", rel)
	}
	full := filepath.Join(root, clean)
	inside, err := filepath.Rel(root, full)
	if err != nil {
		return "", fmt.Errorf("resolve repository path %q: %w", rel, err)
	}
	if inside == ".." || strings.HasPrefix(inside, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("repository path %q escapes project root", rel)
	}
	return full, nil
}

// resolveWithinRoot follows a file or symlink once, verifies that the real
// target is a regular file inside root, and returns the real path. Broken or
// out-of-root symlinks return ok=false instead of failing the audit.
func resolveWithinRoot(root, path string) (real string, isSymlink, ok bool, err error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", false, false, err
	}
	isSymlink = info.Mode()&os.ModeSymlink != 0
	real, err = filepath.EvalSymlinks(path)
	if err != nil {
		return "", isSymlink, false, nil
	}
	inside, err := filepath.Rel(root, real)
	if err != nil || inside == ".." || strings.HasPrefix(inside, ".."+string(os.PathSeparator)) {
		return "", isSymlink, false, nil
	}
	info, err = os.Stat(real)
	if err != nil || !info.Mode().IsRegular() {
		return "", isSymlink, false, nil
	}
	return real, isSymlink, true, nil
}

func resolveProjectRoot(root string) (string, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve project root: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("resolve project root: %w", err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("stat project root: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("project root %s is not a directory", resolved)
	}
	return resolved, nil
}

// BuildPrompt is a single-prompt compatibility wrapper. Use BuildPrompts for
// projects that need chunking.
func BuildPrompt(root string, files []string) (string, []string, int, error) {
	prompts, included, omitted, _, err := BuildPrompts(root, files)
	if err != nil {
		return "", nil, 0, err
	}
	if len(prompts) != 1 {
		return "", nil, 0, errors.New("content requires multiple prompts; use BuildPrompts")
	}
	return prompts[0].Text, included, omitted, nil
}

var (
	ansiEscape   = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)
	oscEscape    = regexp.MustCompile(`\x1b\].*?(?:\x07|\x1b\\)`)
	controlChars = regexp.MustCompile(`[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]`)
)

func sanitizeTerminal(s string) string {
	s = ansiEscape.ReplaceAllString(s, "")
	s = oscEscape.ReplaceAllString(s, "")
	s = controlChars.ReplaceAllString(s, "")
	return s
}

// ParseVerdict accepts a verdict only on the exact final non-empty line of the
// output, without a nonce. Prefer ParseVerdictWithNonce for real audits.
func ParseVerdict(output string) (string, bool) {
	return ParseVerdictWithNonce(output, "")
}

// ParseVerdictWithNonce requires the exact final line to include the per-run
// nonce. This prevents a verdict quoted from the reviewed source from flipping
// the gate.
func ParseVerdictWithNonce(output, nonce string) (string, bool) {
	clean := ansiEscape.ReplaceAllString(output, "")
	clean = strings.ReplaceAll(clean, "\r\n", "\n")
	clean = strings.ReplaceAll(clean, "\r", "\n")
	lines := strings.Split(clean, "\n")
	upperNonce := strings.ToUpper(nonce)
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		upper := strings.ToUpper(line)
		if nonce == "" {
			switch upper {
			case "VERDICT: GO":
				return VerdictGO, true
			case "VERDICT: NO-GO", "VERDICT: NOGO":
				return VerdictNoGo, true
			default:
				return "", false
			}
		}
		switch upper {
		case "VERDICT: GO " + upperNonce:
			return VerdictGO, true
		case "VERDICT: NO-GO " + upperNonce, "VERDICT: NOGO " + upperNonce:
			return VerdictNoGo, true
		default:
			return "", false
		}
	}
	return "", false
}

// tailBuffer keeps the last max bytes, so a final verdict line survives even
// when a verbose agent writes more than the log cap.
type tailBuffer struct {
	buf       []byte
	max       int
	truncated bool
}

func (b *tailBuffer) Write(p []byte) (int, error) {
	if b.max <= 0 {
		b.max = maxAgentOutput
	}
	b.buf = append(b.buf, p...)
	if len(b.buf) > b.max {
		b.buf = b.buf[len(b.buf)-b.max:]
		b.truncated = true
	}
	return len(p), nil
}

func (b *tailBuffer) String() string {
	return string(b.buf)
}

type limitedBuffer struct {
	buf       bytes.Buffer
	max       int
	truncated bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.max <= 0 {
		b.max = maxAgentOutput
	}
	remaining := b.max - b.buf.Len()
	if remaining > 0 {
		if len(p) > remaining {
			_, _ = b.buf.Write(p[:remaining])
			b.truncated = true
		} else {
			_, _ = b.buf.Write(p)
		}
	} else if len(p) > 0 {
		b.truncated = true
	}
	return len(p), nil
}

func (b *limitedBuffer) String() string {
	return b.buf.String()
}
