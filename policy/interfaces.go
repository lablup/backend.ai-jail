package policy

import (
	"io/ioutil"
	"log"
	"path"
	"strings"

	"gopkg.in/yaml.v2"
)

type PathOps int

type PolicyConf struct {
	WhitelistPaths map[string][]string `yaml:"whitelist_paths"`
	ExecAllowance int `yaml:"exec_allowance"`
	ForkAllowance int `yaml:"fork_allowance"`
	MaxChildProcs uint `yaml:"max_child_procs"`
	ExtraEnvs []string `yaml:"extra_envs"`
	PreservedEnvKeys []string `yaml:"preserved_env_keys"`
	TracedSyscalls []string `yaml:"traced_syscalls"`
	ConditionallyAllowedSyscalls []string `yaml:"conditionally_allowed_syscalls"`
	AllowedSyscalls []string `yaml:"allowed_syscalls"`
}

const (
	OP_OPEN PathOps = iota
	OP_ACCESS
	OP_EXEC
	OP_STAT
	OP_CHMOD
)

type SandboxPolicy interface {
	// Should return a boolean representing if access to the path
	// with the given permission is allowed or not.
	CheckPathOp(path string, op PathOps, mode int) bool

	// Should return the number of maximum execv() syscalls.
	// If it returns -1, no limit is imposed.
	GetExecAllowance() int

	// Should return the number of maximum fork()/clone() syscalls.
	// If it returns -1, no limit is imposed.
	GetForkAllowance() int

	// Should return the maximum number of child processes and threads.
	GetMaxChildProcs() uint

	// Should return a boolean representing if executing the executable file in
	// the given path.  Here executing means calling execve().
	CheckPathExecutable(path string) bool

	// Should return additional environment key-value pairs.
	// They will be merged to environment variables of the user process.
	GetExtraEnvs() []string

	// Should return which environment variables are kept intact.
	GetPreservedEnvKeys() []string
}

// =======================================================================
// Policy will replace SandboxPolicy after the implementation is finished.
type Policy struct {
	conf PolicyConf
}

func (p *Policy) CheckPathOp(path string, op PathOps, mode int) bool {
	var allow bool
	switch op {
	case OP_CHMOD:
		allow = false
		for _, prefix := range WhitelistPaths[op] {
			if strings.HasPrefix(path, prefix) {
				allow = true
				break
			}
		}
	default:
		allow = true
	}
	return allow
}

func (p *Policy) GetExecAllowance() int {
	return p.conf.ExecAllowance
}

func (p *Policy) GetForkAllowance() int {
	return p.conf.ForkAllowance
}

func (p *Policy) GetMaxChildProcs() uint {
	return p.conf.MaxChildProcs
}

func (p *Policy) CheckPathExecutable(path string) bool {
	// TODO: always return true currently
	return true
}

func (p *Policy) GetExtraEnvs() []string {
	return p.conf.ExtraEnvs
}

func (p *Policy) GetPreservedEnvKeys() []string {
	return p.conf.PreservedEnvKeys
}

func GeneratePolicy(exec_path string) (SandboxPolicy, error) {
	_, exec_name := path.Split(exec_path)
	switch exec_name {
	case "python-tensorflow":
		return new(PythonTensorFlowPolicy), nil
	case "python", "python2", "python3":
		return new(PythonPolicy), nil
	case "julia":
		return new(JuliaPolicy), nil
	case "git":
		return new(GitPolicy), nil
	default:
		return new(DefaultPolicy), nil
	}
}

func ReadYAMLPolicyFromFile(l *log.Logger, policyFile string, conf *PolicyConf) {
	yamlData, err := ioutil.ReadFile(policyFile)
	if err != nil {
		l.Panic("Error in opening yaml file: #%v ", err)
	}

	err = yaml.Unmarshal(yamlData, &conf)
	if err != nil {
		l.Panic("Yaml unmarshal error: %v", err)
	}
}

func GeneratePolicyFromYAML(l *log.Logger, policyFile string) (SandboxPolicy, error) {
	conf := PolicyConf{}
	ReadYAMLPolicyFromFile(l, policyFile, &conf)

	WhitelistPaths = map[PathOps][]string{
		//OP_OPEN: conf.WhitelistPaths["OP_OPEN"],
		//OP_ACCESS: conf.WhitelistPaths["OP_ACCESS"],
		//OP_EXEC: conf.WhitelistPaths["OP_EXEC"],
		//OP_STAT: conf.WhitelistPaths["OP_STAT"],
		OP_CHMOD: conf.WhitelistPaths["OP_CHMOD"],
	}
	TracedSyscalls = conf.TracedSyscalls
	AllowedSyscalls = conf.AllowedSyscalls
	//ConditionallyAllowedSyscalls = policy.Conditionally_Allowed_Syscalls
	
	// It is OK to return the address of a local variable unlike C.
	return &Policy{conf}, nil
}

// vim: ts=4 sts=4 sw=4 noet
