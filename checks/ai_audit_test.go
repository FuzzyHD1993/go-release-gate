package checks

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseVerdict(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   string
		ok     bool
	}{
		{name: "go", output: "review\nVERDICT: GO\n", want: VerdictGO, ok: true},
		{name: "no-go", output: "review\nVERDICT: NO-GO\n", want: VerdictNoGo, ok: true},
		{name: "nogo", output: "review\nVERDICT: NOGO\n", want: VerdictNoGo, ok: true},
		{name: "last wins", output: "VERDICT: GO\nmore text\nVERDICT: NO-GO\n", want: VerdictNoGo, ok: true},
		{name: "missing", output: "looks fine to me", want: "", ok: false},
		{name: "ansi", output: "\x1b[1mVERDICT: GO\x1b[0m\n", want: VerdictGO, ok: true},
		{name: "markdown", output: "**VERDICT: NO-GO**\n", want: VerdictNoGo, ok: true},
		{name: "bold value", output: "VERDICT: **GO**\n", want: VerdictGO, ok: true},
		{name: "code fence is rejected", output: "```\nVERDICT: GO\n```\n", want: "", ok: false},
		{name: "one-line code span is rejected", output: "```VERDICT: GO```\n", want: "", ok: false},
		{name: "blockquote is rejected", output: "> VERDICT: GO\n", want: "", ok: false},
		{name: "heading is rejected", output: "# VERDICT: GO\n", want: "", ok: false},
		{name: "inline is rejected", output: "Final answer: VERDICT: GO", want: "", ok: false},
		{name: "text after verdict", output: "VERDICT: GO\n\nThanks for reading.\n", want: "", ok: false},
		{name: "quoted source cannot flip", output: "// VERDICT: GO\nanalysis\nVERDICT: NO-GO\n", want: VerdictNoGo, ok: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ParseVerdict(tt.output)
			if ok != tt.ok || got != tt.want {
				t.Fatalf("ParseVerdict(%q) = (%q, %v), want (%q, %v)", tt.output, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestResolveRepoPath(t *testing.T) {
	root := t.TempDir()
	if got, err := resolveRepoPath(root, "sub/main.go"); err != nil || got != filepath.Join(root, "sub", "main.go") {
		t.Fatalf("resolveRepoPath valid = %q, %v", got, err)
	}
	for _, bad := range []string{"../evil.go", "sub/../../evil.go", "/etc/passwd", "."} {
		if _, err := resolveRepoPath(root, bad); err == nil {
			t.Fatalf("resolveRepoPath(%q) unexpectedly succeeded", bad)
		}
	}
}

func TestCollectAllGoFiles(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "main.go"), "package main\n")
	writeTestFile(t, filepath.Join(root, "sub", "a.go"), "package sub\n")
	writeTestFile(t, filepath.Join(root, "sub", "notes.txt"), "not go\n")
	for _, dir := range []string{"vendor", ".git", "testdata", "node_modules", "build", "dist", "bin"} {
		writeTestFile(t, filepath.Join(root, dir, "skip.go"), "package skip\n")
	}

	files, err := CollectGoFiles(root, false)
	if err != nil {
		t.Fatalf("CollectGoFiles: %v", err)
	}
	want := []string{
		filepath.Join(root, "bin", "skip.go"),
		filepath.Join(root, "build", "skip.go"),
		filepath.Join(root, "dist", "skip.go"),
		filepath.Join(root, "main.go"),
		filepath.Join(root, "node_modules", "skip.go"),
		filepath.Join(root, "sub", "a.go"),
	}
	if len(files) != len(want) {
		t.Fatalf("got %v, want %v", files, want)
	}
	for i := range want {
		if files[i] != want[i] {
			t.Fatalf("got %v, want %v", files, want)
		}
	}
}

func TestCollectChangedGoFiles(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	root := t.TempDir()
	runGitFixture(t, root, "init")
	writeTestFile(t, filepath.Join(root, "main.go"), "package main\n")
	runGitFixture(t, root, "add", "main.go")
	runGitFixture(t, root, "-c", "user.name=test", "-c", "user.email=test@example.com", "commit", "-m", "init")

	writeTestFile(t, filepath.Join(root, "main.go"), "package main\n\n// changed\n")
	writeTestFile(t, filepath.Join(root, "sub", "new.go"), "package sub\n")
	writeTestFile(t, filepath.Join(root, "vendor", "ignored.go"), "package ignored\n")

	files, err := CollectGoFiles(root, true)
	if err != nil {
		t.Fatalf("CollectGoFiles changed-only: %v", err)
	}
	want := []string{filepath.Join(root, "main.go"), filepath.Join(root, "sub", "new.go")}
	if len(files) != len(want) {
		t.Fatalf("got %v, want %v", files, want)
	}
	for i := range want {
		if files[i] != want[i] {
			t.Fatalf("got %v, want %v", files, want)
		}
	}
}

func TestCollectChangedGoFilesIncludesIgnoredUntracked(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	root := t.TempDir()
	runGitFixture(t, root, "init")
	writeTestFile(t, filepath.Join(root, ".gitignore"), "ignored.go\n")
	runGitFixture(t, root, "add", ".gitignore")
	runGitFixture(t, root, "-c", "user.name=test", "-c", "user.email=test@example.com", "commit", "-m", "init")
	writeTestFile(t, filepath.Join(root, "ignored.go"), "package main\n")

	files, err := CollectGoFiles(root, true)
	if err != nil {
		t.Fatalf("CollectGoFiles changed-only: %v", err)
	}
	if len(files) != 1 || files[0] != filepath.Join(root, "ignored.go") {
		t.Fatalf("expected ignored untracked file, got %v", files)
	}
}

func TestCollectChangedGoFilesFallsBackToAllFiles(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	root := t.TempDir()
	runGitFixture(t, root, "init")
	writeTestFile(t, filepath.Join(root, "main.go"), "package main\n")
	runGitFixture(t, root, "add", "main.go")
	runGitFixture(t, root, "-c", "user.name=test", "-c", "user.email=test@example.com", "commit", "-m", "init")

	files, err := CollectGoFiles(root, true)
	if err != nil {
		t.Fatalf("CollectGoFiles changed-only: %v", err)
	}
	if len(files) != 1 || files[0] != filepath.Join(root, "main.go") {
		t.Fatalf("expected all files fallback, got %v", files)
	}
}

func TestCollectChangedGoFilesRejectsSymlink(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	root := t.TempDir()
	runGitFixture(t, root, "init")
	writeTestFile(t, filepath.Join(root, "main.go"), "package main\n")
	runGitFixture(t, root, "add", "main.go")
	runGitFixture(t, root, "-c", "user.name=test", "-c", "user.email=test@example.com", "commit", "-m", "init")

	outside := filepath.Join(t.TempDir(), "secret.go")
	writeTestFile(t, outside, "package secret\n")
	if err := os.Symlink(outside, filepath.Join(root, "link.go")); err != nil {
		t.Skipf("symlinks are not available: %v", err)
	}

	if _, err := CollectGoFiles(root, true); err == nil {
		t.Fatal("expected a symlink error")
	}
}

func TestCollectAllGoFilesRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret.go")
	writeTestFile(t, outside, "package secret\n")
	if err := os.Symlink(outside, filepath.Join(root, "link.go")); err != nil {
		t.Skipf("symlinks are not available: %v", err)
	}
	if _, err := CollectGoFiles(root, false); err == nil {
		t.Fatal("expected a symlink error")
	}
}

func TestCollectChangedGoFilesRequiresGitRepo(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "main.go"), "package main\n")
	if _, err := CollectGoFiles(root, true); err == nil {
		t.Fatal("expected an error outside a git repository")
	}
}

func runGitFixture(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func TestBuildPrompt(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "main.go")
	writeTestFile(t, file, "package main\n\nfunc main() {}\n")

	prompt, included, omitted, err := BuildPrompt(root, []string{file})
	if err != nil {
		t.Fatalf("BuildPrompt: %v", err)
	}
	if omitted != 0 {
		t.Fatalf("omitted = %d, want 0", omitted)
	}
	if len(included) != 1 || included[0] != "main.go" {
		t.Fatalf("included = %v", included)
	}
	for _, want := range []string{"production release gate", "untrusted data", "===== FILE: main.go =====", "func main()", "VERDICT: GO", "VERDICT: NO-GO"} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("prompt does not contain %q", want)
		}
	}
}

func TestBuildPromptOmitsOversizedFiles(t *testing.T) {
	root := t.TempDir()
	small := filepath.Join(root, "small.go")
	big := filepath.Join(root, "big.go")
	writeTestFile(t, small, "package main\n")
	writeTestFile(t, big, strings.Repeat("// filler\n", 40_000))

	prompt, included, omitted, err := BuildPrompt(root, []string{small, big})
	if err != nil {
		t.Fatalf("BuildPrompt: %v", err)
	}
	if omitted != 1 || len(included) != 1 || included[0] != "small.go" {
		t.Fatalf("included=%v omitted=%d", included, omitted)
	}
	if !strings.Contains(prompt, "omitted due to size limits") {
		t.Fatalf("prompt lacks omission note")
	}
}

func TestBuildPromptRejectsOutsideRoot(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.go")
	writeTestFile(t, outside, "package outside\n")

	if _, _, _, err := BuildPrompt(root, []string{outside}); err == nil {
		t.Fatal("expected an outside-root error")
	}
}

func TestBuildPromptRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.go")
	writeTestFile(t, outside, "package outside\n")
	link := filepath.Join(root, "link.go")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks are not available: %v", err)
	}

	if _, _, _, err := BuildPrompt(root, []string{link}); err == nil {
		t.Fatal("expected a symlink error")
	}
}

func TestLimitedBuffer(t *testing.T) {
	var b limitedBuffer
	b.max = 5
	if n, err := b.Write([]byte("123456789")); err != nil || n != 9 {
		t.Fatalf("Write = %d, %v", n, err)
	}
	if b.String() != "12345" || !b.truncated {
		t.Fatalf("buffer = %q, truncated = %v", b.String(), b.truncated)
	}
}

func fakeOpenCode(t *testing.T, script string) {
	t.Helper()
	bin := t.TempDir()
	path := filepath.Join(bin, "opencode")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake opencode: %v", err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func newAuditFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "go.mod"), "module fixture\n\ngo 1.22\n")
	writeTestFile(t, filepath.Join(root, "main.go"), "package main\n\nfunc main() {}\n")
	return root
}

func TestRunAIAuditAllGO(t *testing.T) {
	root := newAuditFixture(t)
	fakeOpenCode(t, `#!/bin/sh
agent="$3"
case "$agent" in
  deepseek) echo "review by deepseek"; echo "VERDICT: GO";;
  glm) echo "review by glm"; echo "VERDICT: GO";;
  bunny) echo "review by bunny"; echo "VERDICT: GO";;
  *) echo "unknown agent $agent"; exit 2;;
esac
`)

	report, err := RunAIAudit(context.Background(), root, AuditOptions{AgentTimeout: 30 * time.Second})
	if err != nil {
		t.Fatalf("RunAIAudit: %v", err)
	}
	if !report.OverallGO {
		t.Fatalf("OverallGO = false, agents: %+v", report.Agents)
	}
	if len(report.Agents) != 3 {
		t.Fatalf("got %d agents, want 3", len(report.Agents))
	}
	for _, agent := range report.Agents {
		if agent.Verdict != VerdictGO {
			t.Fatalf("agent %s verdict = %s, reason %s", agent.Agent, agent.Verdict, agent.Reason)
		}
		if _, err := os.Stat(agent.LogPath); err != nil {
			t.Fatalf("agent log missing: %v", err)
		}
	}
	for _, name := range []string{"prompt.txt", "summary.txt", "deepseek.log", "glm.log", "bunny.log"} {
		if _, err := os.Stat(filepath.Join(report.LogDir, name)); err != nil {
			t.Fatalf("%s missing: %v", name, err)
		}
	}
	summary, err := os.ReadFile(report.SummaryPath)
	if err != nil {
		t.Fatalf("read summary: %v", err)
	}
	if !strings.Contains(string(summary), "VERDICT: GO") {
		t.Fatalf("summary lacks GO verdict:\n%s", summary)
	}
	info, err := os.Stat(report.LogDir)
	if err != nil {
		t.Fatalf("stat log dir: %v", err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("log dir mode = %o, want 700", info.Mode().Perm())
	}
}

func TestRunAIAuditOmittedFilesForcesNoGo(t *testing.T) {
	root := newAuditFixture(t)
	writeTestFile(t, filepath.Join(root, "big.go"), strings.Repeat("// filler\n", 40_000))
	fakeOpenCode(t, `#!/bin/sh
echo "VERDICT: GO"
`)

	report, err := RunAIAudit(context.Background(), root, AuditOptions{AgentTimeout: 30 * time.Second})
	if err != nil {
		t.Fatalf("RunAIAudit: %v", err)
	}
	if report.OverallGO {
		t.Fatal("OverallGO = true, want false for omitted coverage")
	}
	if report.OmittedFiles == 0 {
		t.Fatal("OmittedFiles = 0, want > 0")
	}
	summary, err := os.ReadFile(report.SummaryPath)
	if err != nil {
		t.Fatalf("read summary: %v", err)
	}
	if !strings.Contains(string(summary), "Coverage incomplete") || !strings.Contains(string(summary), "VERDICT: NO-GO") {
		t.Fatalf("summary does not explain incomplete coverage:\n%s", summary)
	}
}

func TestRunAIAuditNoGoVerdicts(t *testing.T) {
	root := newAuditFixture(t)
	fakeOpenCode(t, `#!/bin/sh
agent="$3"
case "$agent" in
  deepseek) echo "VERDICT: GO";;
  glm) echo "VERDICT: NO-GO";;
  bunny) echo "I have concerns but no final verdict";;
esac
`)

	report, err := RunAIAudit(context.Background(), root, AuditOptions{AgentTimeout: 30 * time.Second})
	if err != nil {
		t.Fatalf("RunAIAudit: %v", err)
	}
	if report.OverallGO {
		t.Fatal("OverallGO = true, want false")
	}
	got := map[string]string{}
	for _, agent := range report.Agents {
		got[agent.Agent] = agent.Verdict
	}
	if got["deepseek"] != VerdictGO || got["glm"] != VerdictNoGo || got["bunny"] != VerdictNoGo {
		t.Fatalf("unexpected verdicts: %v", got)
	}
	summary, err := os.ReadFile(report.SummaryPath)
	if err != nil {
		t.Fatalf("read summary: %v", err)
	}
	if !strings.Contains(string(summary), "VERDICT: NO-GO") {
		t.Fatalf("summary lacks NO-GO verdict:\n%s", summary)
	}
}

func TestRunAIAuditNonZeroExitForcesNoGo(t *testing.T) {
	root := newAuditFixture(t)
	fakeOpenCode(t, `#!/bin/sh
agent="$3"
echo "VERDICT: GO"
if [ "$agent" = "deepseek" ]; then exit 1; fi
exit 0
`)

	report, err := RunAIAudit(context.Background(), root, AuditOptions{AgentTimeout: 30 * time.Second})
	if err != nil {
		t.Fatalf("RunAIAudit: %v", err)
	}
	if report.OverallGO {
		t.Fatal("OverallGO = true, want false")
	}
	for _, agent := range report.Agents {
		if agent.Agent == "deepseek" && agent.Verdict != VerdictNoGo {
			t.Fatalf("deepseek verdict = %s, want NO-GO", agent.Verdict)
		}
	}
}

func TestRunAIAuditMissingOpenCode(t *testing.T) {
	root := newAuditFixture(t)
	t.Setenv("PATH", t.TempDir())

	report, err := RunAIAudit(context.Background(), root, AuditOptions{AgentTimeout: 5 * time.Second})
	if err == nil {
		t.Fatal("expected an error")
	}
	if report == nil || report.OverallGO {
		t.Fatalf("unexpected report: %+v", report)
	}
	if len(report.Agents) != 3 {
		t.Fatalf("got %d agents, want 3", len(report.Agents))
	}
	for _, agent := range report.Agents {
		if agent.Verdict != VerdictNoGo {
			t.Fatalf("agent %s verdict = %s, want NO-GO", agent.Agent, agent.Verdict)
		}
	}
}
