package policy

type JuliaPolicy struct {
}

func (p JuliaPolicy) CheckPathOp(path string, op PathOps, mode int) bool {
	for _, matcher := range defaultConf.WhitelistPaths[op] {
		if matcher.Match(path) {
			return true
		}
	}
	return false
}

func (p JuliaPolicy) GetExecAllowance() int {
	return 0
}

func (p JuliaPolicy) GetForkAllowance() int {
	return -1
}

func (p JuliaPolicy) GetMaxChildProcs() uint {
	return 32
}

func (p JuliaPolicy) GetExtraEnvs() []string {
	return []string{}
}

func (p JuliaPolicy) GetPreservedEnvKeys() []string {
	return []string{
		"HOME", "PATH", "LANG",
		"PYENV_ROOT", "PYTHONPATH",
		"PYTHONUNBUFFERED",
		"JULIA_CPU_CORES",
		"JULIA_PKGDIR",
		"OPENBLAS_NUM_THREADS",
		"MPLCONFIGDIR",
		"LD_LIBRARY_PATH",
		"LD_PRELOAD",
	}
}
