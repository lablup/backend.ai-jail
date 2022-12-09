package policy

import (
	"fmt"
	"io/ioutil"
	"log"

	glob "github.com/gobwas/glob"
	yaml "gopkg.in/yaml.v2"
)

type SandboxPolicy interface {
	CheckPathOp(path string, op PathOps, mode int) bool
	GetExecAllowance() int
	GetForkAllowance() int
	GetMaxChildProcs() int
	GetExtraEnvs() []string
	GetPreservedEnvKeys() []string
	GetTracedSyscalls() []string
	GetAllowedSyscalls() []string
}

type PathOps int

const (
	OP_OPEN PathOps = iota
	OP_ACCESS
	OP_EXEC
	OP_STAT
	OP_CHMOD
)

var pathOpsNameMap map[string]PathOps

type PatternMatcher struct {
	glob.Glob
}

var defaultConf PolicyConf

func init() {
	pathOpsNameMap = map[string]PathOps{
		"OP_OPEN":   OP_OPEN,
		"OP_ACCESS": OP_ACCESS,
		"OP_EXEC":   OP_EXEC,
		"OP_STAT":   OP_STAT,
		"OP_CHMOD":  OP_CHMOD,
	}

	confFilename := fmt.Sprintf("./default-policies/default-policy.%s.yml", "amd64")

	ymlFile, err := ioutil.ReadFile(confFilename)
	if err != nil {
		log.Fatal(err)
	}

	err = yaml.Unmarshal(ymlFile, &defaultConf)
	if err != nil {
		log.Fatal(err)
	}
}
