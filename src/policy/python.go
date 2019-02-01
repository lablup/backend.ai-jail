package policy

type PythonPolicy struct {
}

func (p PythonPolicy) CheckPathOp(path string, op PathOps, mode int) bool {
	for _, matcher := range defaultConf.WhitelistPaths[op] {
		if matcher.Match(path) {
			return true
		}
	}
	return false
}

func (p PythonPolicy) GetExecAllowance() int {
	return 0
}

func (p PythonPolicy) GetForkAllowance() int {
	// Note: pyzmq performs clone() twice on initialization.
	return -1
}

func (p PythonPolicy) GetMaxChildProcs() uint {
	return 32
}

func (p PythonPolicy) GetExtraEnvs() []string {
	return []string{}
}

func (p PythonPolicy) GetPreservedEnvKeys() []string {
	return []string{
		"HOME", "PATH", "LANG",
		"PYENV_ROOT", "PYTHONPATH",
		"PYTHONUNBUFFERED",
		"MPLCONFIGDIR",
		"OPENBLAS_NUM_THREADS",
		"LD_LIBRARY_PATH",
		"LD_PRELOAD",
	}
}
