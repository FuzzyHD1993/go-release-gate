//go:build !unix

package checks

import (
	"os/exec"
	"time"
)

func configureProcessGroup(cmd *exec.Cmd) {
	cmd.WaitDelay = 5 * time.Second
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return cmd.Process.Kill()
	}
}
