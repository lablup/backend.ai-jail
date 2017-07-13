package policy

import (
	"io/ioutil"
	"log"
	"strings"

	"gopkg.in/yaml.v2"
)

type SandboxPolicy struct {
	conf PolicyConf
}

func (p *SandboxPolicy) CheckPathOp(path string, op PathOps, mode int) bool {
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

func (p *SandboxPolicy) GetExecAllowance() int {
	return p.conf.ExecAllowance
}

func (p *SandboxPolicy) GetForkAllowance() int {
	return p.conf.ForkAllowance
}

func (p *SandboxPolicy) GetMaxChildProcs() uint {
	return p.conf.MaxChildProcs
}

func (p *SandboxPolicy) CheckPathExecutable(path string) bool {
	// TODO: always return true currently
	return true
}

func (p *SandboxPolicy) GetExtraEnvs() []string {
	return p.conf.ExtraEnvs
}

func (p *SandboxPolicy) GetPreservedEnvKeys() []string {
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

	// It is OK to return the address of a local variable unlike C.
	return SandboxPolicy{conf}, nil
}

// vim: ts=4 sts=4 sw=4 noet
