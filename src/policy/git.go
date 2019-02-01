package policy

import (
	"strings"
)

type GitPolicy struct {
}

func (p *GitPolicy) CheckPathOp(path string, op PathOps, mode int) bool {
	var allow bool
	switch op {
	case OP_CHMOD:
		allow = strings.HasPrefix(path, "/home/work/")
	default:
		allow = true
	}
	return allow
}

func (p *GitPolicy) GetExecAllowance() int {
	// Required to spawn a sub-shell in pseudo-tty
	return 1
}

func (p *GitPolicy) GetForkAllowance() int {
	// Note: pyzmq performs clone() twice on initialization.
	return -1
}

func (p *GitPolicy) GetMaxChildProcs() uint {
	return 32
}

func (p *GitPolicy) CheckPathExecutable(path string) bool {
	// TODO: implement
	return true
}

func (p *GitPolicy) GetExtraEnvs() []string {
	return []string{}
}

func (p *GitPolicy) GetPreservedEnvKeys() []string {
	return []string{
		"HOME", "PATH", "LANG", "TERM",
		"USER", "SHELL",
		"PYENV_ROOT", "PYTHONPATH",
		"MPLCONFIGDIR",
		"LD_LIBRARY_PATH",
		"LD_PRELOAD",
	}
}
