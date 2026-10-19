//go:build unix

package checks

import (
	"os/exec"
	"syscall"
	"time"
)

// configureProcessGroup puts the child into its own process group so a timeout
// also terminates descendants that inherited its stdout/stderr pipes.
func configureProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = 5 * time.Second
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if err == syscall.ESRCH {
			return nil
		}
		return err
	}
}
