package policy

import (
	"io/ioutil"
	"log"
	"strings"

	"gopkg.in/yaml.v2"
	seccomp "github.com/seccomp/libseccomp-golang"
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

func GeneratePolicyFromYAML(l *log.Logger, policyFile string) (SandboxPolicy, error) {
	conf := defaultConf

	yamlData, err := ioutil.ReadFile(policyFile)
	if err != nil {
		l.Println("No policy is given. Use default config.")
	} else {
		// Update default conf with custom config.
		err = yaml.Unmarshal(yamlData, &conf)
		if err != nil {
			l.Panic("Yaml unmarshal error: %v", err)
		}
	}

	WhitelistPaths = map[PathOps][]string{
		//OP_OPEN: conf.WhitelistPaths["OP_OPEN"],
		//OP_ACCESS: conf.WhitelistPaths["OP_ACCESS"],
		//OP_EXEC: conf.WhitelistPaths["OP_EXEC"],
		//OP_STAT: conf.WhitelistPaths["OP_STAT"],
		OP_CHMOD: conf.WhitelistPaths["OP_CHMOD"],
	}
	TracedSyscalls = conf.TracedSyscalls
	AllowedSyscalls = conf.AllowedSyscalls
	// TODO: how to read conditionally_allowed_syscalls?
	ConditionallyAllowedSyscalls = map[string]seccomp.ScmpCondition{
	// To make it tracee's initial synchronization working
	//"kill": {1, seccomp.CompareEqual, uint64(syscall.SIGSTOP), 0},
	}
	
	// It is OK to return the address of a local variable unlike C.
	return &Policy{conf}, nil
}

// vim: ts=4 sts=4 sw=4 noet
