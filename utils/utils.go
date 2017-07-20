package utils

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"syscall"
)

func FilterEnvs(envs []string, preservedKeys []string) []string {
	filteredEnvs := []string{}
	for _, entry := range envs {
		var kept bool = false
		for _, key := range preservedKeys {
			if strings.HasPrefix(entry, key+"=") {
				kept = true
				break
			}
		}
		if kept {
			filteredEnvs = append(filteredEnvs, entry)
		}
	}
	return filteredEnvs
}

func GetExecutable(pid int) (string, error) {
	const deletedTag = " (deleted)"
	execPath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return execPath, err
	}
	execPath = strings.TrimSuffix(execPath, deletedTag)
	execPath = strings.TrimPrefix(execPath, deletedTag)
	switch execPath {
	case "/bin/sh", "/bin/bash", "/bin/dash":
		rawData := make([]byte, 1024)
		file, err := os.Open(fmt.Sprintf("/proc/%d/cmdline", pid))
		if err != nil {
			return execPath, err
		}
		file.Read(rawData)
		file.Close()
		data := string(rawData[:])
		cmd := strings.Split(data, "\x00")
		if !path.IsAbs(cmd[1]) && cmd[1] != "/usr/bin/env" {
			cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
			if err != nil {
				return execPath, err
			}
			execPath = path.Join(cwd, cmd[1])
		} else {
			execPath = cmd[1]
		}
	}
	return execPath, nil
}

func ReadString(pid int, addr uintptr) string {
	out := make([]byte, syscall.PathMax)
	syscall.PtracePeekData(pid, addr, out)
	// Try to find the index of first null character
	length := bytes.IndexByte(out, 0)
	if length == -1 {
		length = syscall.PathMax
	}
	return string(out[:length])
}

func GetAbsPathAs(path_ string, pid int) string {
	if path.IsAbs(path_) {
		return path.Clean(path_)
	} else {
		pwdPath := fmt.Sprintf("/proc/%d/cwd", pid)
		pwd, _ := os.Readlink(pwdPath)
		path_ = path.Clean(path_)
		return path.Join(pwd, path_)
	}
}

func CountChildren(pid int) uint {
	var ignoreInt int
	var ignoreStr string
	var numThreads uint = 0
	statsPath := fmt.Sprintf("/proc/%d/stats", pid)
	f, _ := os.Open(statsPath)
	defer f.Close()
	data, _ := ioutil.ReadAll(f)
	leftParenPos := bytes.Index(data, []byte("("))
	rightParenPos := bytes.LastIndex(data, []byte(")"))
	if leftParenPos < 0 || rightParenPos < 0 {
		numThreads = 1
	} else {
		_, err := fmt.Fscan(
			bytes.NewBuffer(data[rightParenPos+2:]),
			&ignoreStr,
			&ignoreInt,
			&ignoreInt,
			&ignoreInt,
			&ignoreInt,
			&ignoreInt,
			&ignoreInt,
			&ignoreInt,
			&ignoreInt,
			&ignoreInt,
			&ignoreInt,
			&ignoreInt,
			&ignoreInt,
			&ignoreInt,
			&ignoreInt,
			&ignoreInt,
			&ignoreInt,
			&numThreads,
			&ignoreInt,
			&ignoreInt,
			&ignoreInt,
			&ignoreInt,
		)
		if err != nil {
			numThreads = 1
		}
	}
	var sumChildrenThreads uint = 0
	taskEntries, _ := ioutil.ReadDir(fmt.Sprintf("/proc/%d/task/", pid))
	for _, tid := range taskEntries {
		childrenPath := fmt.Sprintf("/proc/%d/task/%s/children", pid, tid)
		f, _ := os.Open(childrenPath)
		data, _ := ioutil.ReadAll(f)
		defer f.Close()
		childEntries := strings.Split(string(data), " ")
		for childPid := range childEntries {
			if childPid != pid {
				sumChildrenThreads += CountChildren(childPid)
			}
		}
	}
	return numThreads + sumChildrenThreads
}
