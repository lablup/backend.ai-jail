package policy

import (
	"io/ioutil"
	"log"
	"strings"

	"gopkg.in/yaml.v2"
)

type SandboxPolicy interface {
	CheckPathOp(path string, op PathOps, mode int) bool
	GetExecAllowance() int
	GetForkAllowance() int
	GetMaxChildProcs() uint
	GetExtraEnvs() []string
	GetPreservedEnvKeys() []string
	GetTracedSyscalls() []string
	GetAllowedSyscalls() []string
}

type FileBasedPolicy struct {
	FileName string
	conf     PolicyConf
}

func (p FileBasedPolicy) CheckPathOp(path string, op PathOps, mode int) bool {
	var allow bool
	switch op {
	case OP_CHMOD:
		allow = false
		for _, prefix := range p.conf.WhitelistPaths[op] {
			if strings.HasPrefix(path, prefix) {
				allow = true
				break
			}
		}
	case OP_EXEC:
		allow = true
	default:
		allow = true
	}
	return allow
}

func (p FileBasedPolicy) GetExecAllowance() int {
	return p.conf.ExecAllowance
}

func (p FileBasedPolicy) GetForkAllowance() int {
	return p.conf.ForkAllowance
}

func (p FileBasedPolicy) GetMaxChildProcs() uint {
	return p.conf.MaxChildProcs
}

func (p FileBasedPolicy) GetExtraEnvs() []string {
	return p.conf.ExtraEnvs
}

func (p FileBasedPolicy) GetPreservedEnvKeys() []string {
	return p.conf.PreservedEnvKeys
}

func (p FileBasedPolicy) GetTracedSyscalls() []string {
	return p.conf.TracedSyscalls
}

func (p FileBasedPolicy) GetAllowedSyscalls() []string {
	return p.conf.AllowedSyscalls
}

func GeneratePolicyFromYAML(l *log.Logger, policyFile string) (FileBasedPolicy, error) {
	var conf PolicyConf

	yamlData, err := ioutil.ReadFile(policyFile)
	if err != nil {
		l.Println("Cannot read the policy file. Falling back to default policy...")
		conf = defaultConf
	} else {
		// Update default conf with custom config.
		err = yaml.Unmarshal(yamlData, &conf)
		if err != nil {
			return FileBasedPolicy{}, err
		}
	}

	// It is OK to return the address of a local variable unlike C.
	return FileBasedPolicy{policyFile, conf}, nil
}

// vim: ts=4 sts=4 sw=4 noet
