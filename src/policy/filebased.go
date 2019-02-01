package policy

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/fatih/color"
	glob "github.com/gobwas/glob"
	yaml "gopkg.in/yaml.v2"
)

type PolicyConf struct {
	DiffToDefault    bool                         `yaml:"diff_to_default"`
	WhitelistPaths   map[PathOps][]PatternMatcher `yaml:"whitelist_paths"`
	ExecAllowance    int                          `yaml:"exec_allowance"`
	ForkAllowance    int                          `yaml:"fork_allowance"`
	MaxChildProcs    int                          `yaml:"max_child_procs"`
	ExtraEnvs        []string                     `yaml:"extra_envs"`
	PreservedEnvKeys []string                     `yaml:"preserved_env_keys"`
	TracedSyscalls   []string                     `yaml:"traced_syscalls"`
	AllowedSyscalls  []string                     `yaml:"allowed_syscalls"`
}

func (o *PathOps) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var raw string
	if err := unmarshal(&raw); err != nil {
		return err
	}
	var ok bool
	if *o, ok = pathOpsNameMap[raw]; !ok {
		return fmt.Errorf("invalid path operation name: %s", raw)
	}
	return nil
}

func (p *PatternMatcher) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var raw string
	var err error
	if err = unmarshal(&raw); err != nil {
		return err
	}
	var g glob.Glob
	if g, err = glob.Compile(raw); err != nil {
		return err
	}
	*p = PatternMatcher{g}
	return nil
}

type FileBasedPolicy struct {
	FileName string
	conf     PolicyConf
}

func (p FileBasedPolicy) CheckPathOp(path string, op PathOps, mode int) bool {
	for _, matcher := range p.conf.WhitelistPaths[op] {
		if matcher.Match(path) {
			return true
		}
	}
	return false
}

func (p FileBasedPolicy) GetExecAllowance() int {
	return p.conf.ExecAllowance
}

func (p FileBasedPolicy) GetForkAllowance() int {
	return p.conf.ForkAllowance
}

func (p FileBasedPolicy) GetMaxChildProcs() int {
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

func GeneratePolicyFromYAML(policyFile string) (FileBasedPolicy, error) {

	var conf *PolicyConf = new(PolicyConf)
	l := log.New(os.Stderr, "", 0)

	if policyFile == "[default]" {
		*conf = defaultConf
	} else {
		yamlData, err := ioutil.ReadFile(policyFile)
		if err != nil {
			color.Set(color.FgYellow)
			l.Println("Cannot read the policy file. Falling back to default policy...")
			color.Unset()
			policyFile = "[default]"
			*conf = defaultConf
		} else {
			// Update default conf with custom config.
			err = yaml.Unmarshal(yamlData, conf)
			if err != nil {
				return FileBasedPolicy{}, err
			}
			// We use fixed set of traced syscalls.
			conf.TracedSyscalls = defaultConf.TracedSyscalls
		}
	}

	// Merge if the policy only states the additional differences of environ/syscalls to the default.
	// The resource limit counts are not merged but just used as-is.
	if conf.DiffToDefault {
		mergedExtraEnvs := make(map[string]string)
		mergedPreservedEnvKeys := make(map[string]bool)
		mergedAllowedSyscalls := make(map[string]bool)

		for _, e := range defaultConf.ExtraEnvs {
			split := strings.SplitN(e, "=", 2)
			mergedExtraEnvs[split[0]] = split[1]
		}
		for _, e := range conf.ExtraEnvs {
			split := strings.SplitN(e, "=", 2)
			mergedExtraEnvs[split[0]] = split[1]
		}
		conf.ExtraEnvs = nil
		for k, v := range mergedExtraEnvs {
			conf.ExtraEnvs = append(conf.ExtraEnvs, fmt.Sprintf("%s=%s", k, v))
		}

		for _, k := range defaultConf.PreservedEnvKeys {
			mergedPreservedEnvKeys[k] = true
		}
		for _, k := range conf.PreservedEnvKeys {
			mergedPreservedEnvKeys[k] = true
		}
		conf.PreservedEnvKeys = nil
		for k, _ := range mergedPreservedEnvKeys {
			conf.PreservedEnvKeys = append(conf.PreservedEnvKeys, k)
		}

		for _, s := range defaultConf.AllowedSyscalls {
			mergedAllowedSyscalls[s] = true
		}
		for _, s := range conf.AllowedSyscalls {
			mergedAllowedSyscalls[s] = true
		}
		conf.AllowedSyscalls = []string{}
		for s, _ := range mergedAllowedSyscalls {
			conf.AllowedSyscalls = append(conf.AllowedSyscalls, s)
		}
	}

	return FileBasedPolicy{policyFile, *conf}, nil
}
