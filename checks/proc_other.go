//go:build !unix

package checks

import (
	"os/exec"
	"time"
)

func configureProcessGroup(cmd *exec.Cmd) {
	cmd.WaitDelay = 5 * time.Second
}
