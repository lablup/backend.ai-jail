package policy

type PythonTensorFlowPolicy struct {
}

func (p PythonTensorFlowPolicy) CheckPathOp(path string, op PathOps, mode int) bool {
	for _, matcher := range defaultConf.WhitelistPaths[op] {
		if matcher.Match(path) {
			return true
		}
	}
	return false
}

func (p PythonTensorFlowPolicy) GetExecAllowance() int {
	return 0
}

func (p PythonTensorFlowPolicy) GetForkAllowance() int {
	// Note: pyzmq performs clone() twice on initialization.
	return -1
}

func (p PythonTensorFlowPolicy) GetMaxChildProcs() uint {
	return 32
}

func (p PythonTensorFlowPolicy) GetExtraEnvs() []string {
	return []string{}
}

func (p PythonTensorFlowPolicy) GetPreservedEnvKeys() []string {
	return []string{
		"HOME", "PATH", "LANG",
		"PYENV_ROOT", "PYTHONPATH",
		"PYTHONUNBUFFERED",
		"MPLCONFIGDIR",
		"OPENBLAS_NUM_THREADS",
		"OMP_NUM_THREADS",
		// for nvidia-docker base image
		"CUDA_VERSION",
		"CUDA_PKG_VERSION",
		"LD_LIBRARY_PATH",
		"LD_PRELOAD",
	}
}
