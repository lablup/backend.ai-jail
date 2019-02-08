// This ptrace-based jail assumes linux/amd64 platforms.

/*
Command-line usage:
	./jail <child_args ...>  // use default policy
	./jail -policy <policy_file> <child_args ...>

Example:
	./jail -policy python3.yml /bin/sh /home/backend.ai/run.sh
*/
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"

	"policy"
	"utils"
	"tracer"

	"github.com/fatih/color"
	//"github.com/lablup/backend.ai-jail/policy"
	//"github.com/lablup/backend.ai-jail/utils"
	seccomp "github.com/seccomp/libseccomp-golang"

)

type Exit struct{ Code int }

var (
	myExecPath, _  = utils.GetExecutable(os.Getpid())
	myPath         = filepath.Dir(myExecPath)
	intraJailPath  = myExecPath
	arch, _        = seccomp.GetNativeArch()
	id_Open, _     = seccomp.GetSyscallFromNameByArch("open", arch)
	id_Stat, _     = seccomp.GetSyscallFromNameByArch("stat", arch)
	id_OpenAt, _   = seccomp.GetSyscallFromNameByArch("openat", arch)
	id_Access, _   = seccomp.GetSyscallFromNameByArch("access", arch)
	id_Clone, _    = seccomp.GetSyscallFromNameByArch("clone", arch)
	id_Fork, _     = seccomp.GetSyscallFromNameByArch("fork", arch)
	id_Vfork, _    = seccomp.GetSyscallFromNameByArch("vfork", arch)
	id_Execve, _   = seccomp.GetSyscallFromNameByArch("execve", arch)
	id_ExecveAt, _ = seccomp.GetSyscallFromNameByArch("execveat", arch)
	id_Kill, _     = seccomp.GetSyscallFromNameByArch("kill", arch)
	id_Killpg, _   = seccomp.GetSyscallFromNameByArch("killpg", arch)
	id_Tkill, _    = seccomp.GetSyscallFromNameByArch("tkill", arch)
	id_Tgkill, _   = seccomp.GetSyscallFromNameByArch("tgkill", arch)
	id_Chmod, _    = seccomp.GetSyscallFromNameByArch("chmod", arch)
	id_Fchmodat, _ = seccomp.GetSyscallFromNameByArch("fchmodat", arch)
)

var debug bool = false
var watch bool = false
var noop bool = false
var policyInst policy.SandboxPolicy
var policyFile string
var childMode bool = false
var execCount int = 0
var forkCount int = 0
var childCount int = 1
var maxChildCount int = 0

type WaitResult struct {
	pid    int
	err    error
	status syscall.WaitStatus
}

func waitChildStop(pid int) syscall.WaitStatus {
	var status syscall.WaitStatus
	for {
		p, err := syscall.Wait4(pid, &status, syscall.WSTOPPED, nil)
		if err == syscall.EINTR || p < 0 {
			continue
		} else {
			break
		}
	}
	return status
}

func waitMonitor(pid int, childrenWaits chan WaitResult) {
	var status syscall.WaitStatus
	for {
		traceePid, err := syscall.Wait4(-1, &status, syscall.WALL, nil)

		if err != nil {
			switch err.(syscall.Errno) {
			case syscall.EINTR:
				// Retry the wait system call.
				continue
			case syscall.ECHILD:
				// No child processes found. Terminate.
				break
			default:
				utils.LogError("unexpected errno %s", err)
				break
			}
		}
		childrenWaits <- WaitResult{int(traceePid), err, status}
		//msgQueue.Append(childrenWaits)
		if status.Exited() && traceePid == pid {
			break
		}
	}
	if debug {
		utils.LogInfo("monitoring goroutine terminating.")
	}
}

func handlingMySignal(pid int, signal os.Signal) bool{

	switch signal {
	case os.Interrupt, syscall.SIGTERM:
		// Terminate all my children.
		// Since we set Setsid: true in SysProcAttr of syscall.ForkExec(),
		// the signals we receive are NOT automatically delivered to children.
		// We control the SIGINT/SIGTERM behaviour gracefully for later
		// extension of Sorna.
		pgid, _ := syscall.Getpgid(pid)
		syscall.Kill(pgid, syscall.SIGKILL)

		var status syscall.WaitStatus
		syscall.Wait4(pid, &status, syscall.WALL, nil)
		return true
	}
	return false
}

func monitoringSyscall(pid int, result WaitResult) bool {

	var signalToChild syscall.Signal = 0
	l := log.New(os.Stderr,"",0)

	if result.status.Exited() {
		if debug {
			utils.LogInfo("EXIT (pid %d) status %d\n", result.pid, result.status.ExitStatus())
		}
		if pid == result.pid {
			if debug {
				utils.LogInfo("Our very child has exited. Done.")
			}
			if watch {
				utils.LogInfo("Max child count: %d.", maxChildCount)
			}
			return true
		} else if result.pid == -1 {
			if debug {
				utils.LogError("waitpid error: %s (exit status %d). Terminating.", result.err, result.status.ExitStatus())
			}
			return true
		} else {
			// If we attach grand-children processes, this may be the case.
			childCount--
			if debug {
				utils.LogInfo("childCount is now %d\n", childCount)
			}
		}
	}

	if result.status.Signaled() {
		return false
	}

	if !result.status.Stopped() {
		return false
	}

	// Okay, we now have to deal with tracing stops.

	stopsig := result.status.StopSignal()

	if debug {
		utils.LogDebug("Received signal: 0x%x (%d) \"%s\"", uint(stopsig), uint(stopsig), stopsig)
	}

	childStopped := false
	event := uint(result.status) >> 16

	switch event {
	case 0:
		// pass
	case tracer.PTRACE_EVENT_STOP:
		switch stopsig {
		case syscall.SIGSTOP, syscall.SIGTSTP, syscall.SIGTTOU, syscall.SIGTTIN:
			childStopped = true
			if debug {
				utils.LogDebug("group-stop detected")
			}
		}
	default:
		// pass
	}

	switch stopsig {
	case syscall.SIGSTOP:
		// pass
	case syscall.SIGTRAP:

		eventCause := ((uint(result.status) >> 8) & (^uint(syscall.SIGTRAP))) >> 8
		if debug {
			utils.LogDebug("event-cause: %d\n", eventCause)
		}

		switch eventCause {
		case tracer.PTRACE_EVENT_SECCOMP:
			var extraInfo string = ""
			allow := true
			// Linux syscall convention for x86_64 arch:
			//  - rax: syscall number
			//  - rdi: 1st param
			//  - rsi: 2nd param
			//  - rdx: 3rd param
			//  - r10: 4th param
			//  - r8: 5th param
			//  - r9: 6th param
			var regs syscall.PtraceRegs
			for {
				err := tracer.PtraceGetRegs(result.pid, &regs)
				if err != nil {
					errno := err.(syscall.Errno)
					if errno == syscall.EBUSY || errno == syscall.EFAULT || errno == syscall.ESRCH {
						continue
					}
				}
				break
			}
			syscallId := uint(regs.Orig_rax)
			if debug {
				sn, _ := seccomp.ScmpSyscall(syscallId).GetName()
				utils.LogDebug("seccomp trap (%d %s)", syscallId, sn)
			}
			switch seccomp.ScmpSyscall(syscallId) {
			case id_Fork, id_Vfork, id_Clone:
				execPath, _ := utils.GetExecutable(result.pid)
				if execPath == myExecPath {
					allow = true
				} else if execPath == intraJailPath {
					allow = true
				} else {
					maxForks := policyInst.GetForkAllowance()
					allow = (maxForks == -1 || forkCount < maxForks)
					forkCount++
				}
				maxCount := policyInst.GetMaxChildProcs()
				allow = allow && (maxCount == -1 || childCount < maxCount)
				if debug {
					utils.LogInfo("fork owner: %s\n",execPath)
				}
			case id_Tgkill:
				targetTgid := int(regs.Rdi)
				targetTid := int(regs.Rsi)
				signum := syscall.Signal(uint(regs.Rdx))
				switch signum {
				case syscall.SIGKILL, syscall.SIGINT, syscall.SIGTERM:
					allow = (targetTgid != os.Getpid() &&
						targetTid != pid &&
						targetTid != os.Getpid() &&
						!(targetTid == 0 && result.pid == pid) &&
						targetTid != 1)
				default:
					allow = true
				}
			case id_Kill, id_Killpg, id_Tkill:
				targetPid := int(regs.Rdi)
				signum := syscall.Signal(uint(regs.Rsi))
				switch signum {
				case syscall.SIGKILL, syscall.SIGINT, syscall.SIGTERM:
					allow = (targetPid != pid &&
						targetPid != os.Getpid() &&
						!(targetPid == 0 && result.pid == pid) &&
						targetPid != 1)
				default:
					allow = true
				}
			case id_Execve, id_ExecveAt:
				execPath, _ := utils.GetExecutable(result.pid)
				if execPath == myExecPath {
					allow = true
				} else if execPath == intraJailPath {
					allow = true
				} else if policyInst.CheckPathOp(execPath, policy.OP_EXEC, 0) {
					allow = true
				} else {
					maxExec := policyInst.GetExecAllowance()
					allow = (maxExec == -1 || execCount < maxExec)
					execCount++
				}
				extraInfo = fmt.Sprintf("execve from %s", execPath)
			case id_Open:
				pathPtr := uintptr(regs.Rdi)
				path := utils.ReadString(result.pid, pathPtr)
				path = utils.GetAbsPathAs(path, result.pid)
				// rsi is flags
				mode := int(regs.Rdx)
				allow = policyInst.CheckPathOp(path, policy.OP_OPEN, mode)
				extraInfo = path
			case id_Access:
				pathPtr := uintptr(regs.Rdi)
				path := utils.ReadString(result.pid, pathPtr)
				path = utils.GetAbsPathAs(path, result.pid)
				mode := int(regs.Rsi)
				allow = policyInst.CheckPathOp(path, policy.OP_ACCESS, mode)
				extraInfo = path
			case id_Fchmodat:
				pathPtr := uintptr(regs.Rsi)
				path := utils.ReadString(result.pid, pathPtr)
				path = utils.GetAbsPathAs(path, result.pid)
				mode := int(regs.Rdx)
				allow = policyInst.CheckPathOp(path, policy.OP_CHMOD, mode)
				extraInfo = fmt.Sprintf("%s 0o%o", path, mode)
			case id_Chmod:
				pathPtr := uintptr(regs.Rdi)
				path := utils.ReadString(result.pid, pathPtr)
				path = utils.GetAbsPathAs(path, result.pid)
				mode := int(regs.Rsi)
				allow = policyInst.CheckPathOp(path, policy.OP_CHMOD, mode)
				extraInfo = fmt.Sprintf("%s 0o%o", path, mode)
			default:
				allow = true
			}
			if !allow {
				if debug || watch {
					syscallName, _ := seccomp.ScmpSyscall(syscallId).GetName()
					color.Set(color.FgRed)
					if extraInfo != "" {
						l.Printf("blocked syscall %s (%s)", syscallName, extraInfo)
					} else {
						l.Printf("blocked syscall %s", syscallName)
					}
					color.Unset()
				}
				// If we are not in the watch mode...
				if !watch {
					// Block the system call with permission error
					regs.Orig_rax = 0xFFFFFFFFFFFFFFFF // -1
					regs.Rax = 0xFFFFFFFFFFFFFFFF - uint64(syscall.EPERM) + 1
					tracer.PtraceSetRegs(result.pid,&regs)
				}
			} else {
				if debug {
					syscallName, _ := seccomp.ScmpSyscall(syscallId).GetName()
					color.Set(color.FgGreen)
					if extraInfo != "" {
						l.Printf("allowed syscall %s (%s)", syscallName, extraInfo)
					} else {
						l.Printf("allowed syscall %s", syscallName)
					}
					color.Unset()
				}
			}
		case tracer.PTRACE_EVENT_CLONE,
			tracer.PTRACE_EVENT_FORK,
			tracer.PTRACE_EVENT_VFORK:
			childPid, _ := tracer.PtraceGetEventMsg(result.pid)
			tracer.PtraceSeize(pid, tracer.OurPtraceOpts)
			childCount++
			if maxChildCount < childCount {
				maxChildCount = childCount
			}
			if debug {
				utils.LogInfo("Attached to new child %d\n", childPid)
				utils.LogInfo("childCount is now %d\n", childCount)
			}
		case tracer.PTRACE_EVENT_EXEC:
			if debug {
				utils.LogDebug("Exec Catched")
			}
		case tracer.PTRACE_EVENT_STOP:
			// already processed above
		case 0:
			// ignore
		default:
			if debug || watch {
				utils.LogError("Unknown trap cause: %d\n", result.status.TrapCause())
			}
		}
	//case syscall.SIGCHLD:
	// SIGCHLD is not a reliable method to determine grand-children exits,
	// because multiple signals generated in a short period time may be merged
	// into a single one.
	// Instead, we use TRACE_FORK ptrace options and attaching grand-children
	// processes manually.
	default:
		// Transparently deliver other signals.
		if !childStopped {
			signalToChild = stopsig
			if debug {
				utils.LogInfo("Injecting unhandled signal: %s",signalToChild)
			}
		}
	}

	var err error
	if childStopped && stopsig != syscall.SIGTRAP {
		// may be a group-stop; we need to keep the child stopped.
		if debug {
			utils.LogDebug("ptrace-listen")
		}
		_, err = tracer.PtraceListen(result.pid, 0)
	} else {
		if debug {
			utils.LogDebug("ptrace-cont")
		}
		err = tracer.PtraceCont(result.pid, int(signalToChild))
	}

	if err != nil && err.(syscall.Errno) != 0 {
		utils.LogDebug("pid : %d | result.PID : %d",pid,result.pid)
		utils.LogDebug("Parent pid : %d",syscall.Getpid())
		utils.LogError("ptrace-continue error %s", err)
		errno := err.(syscall.Errno)
		if errno == syscall.EBUSY || errno == syscall.EFAULT || errno == syscall.ESRCH {
			return true
		}
	}
	return false
}


func traceProcess(l *log.Logger, pid int) {

	var isTerminated bool
	var isTerminated2 bool

	//msgQueue = queue.New()

	mySignals := make(chan os.Signal, 100)
	childrenWaits := make(chan WaitResult, 100)

	signal.Notify(mySignals, os.Interrupt, syscall.SIGTERM)
	signal.Ignore(syscall.SIGSTOP)
	signal.Ignore(syscall.SIGTTOU)
	signal.Ignore(syscall.SIGTTIN)
	signal.Ignore(syscall.SIGTSTP)

	// Child is first-stopped.
	status := waitChildStop(pid)
	if !status.Stopped() || status.StopSignal() != syscall.SIGSTOP {
		utils.LogError("Unexpected wait status 0x%x", uint(status))
		return
	}

	ret, seizeErr := tracer.PtraceSeize(pid, tracer.OurPtraceOpts)
	if ret != 0 {
		utils.LogError("PtraceSeize error: %d\n", seizeErr)
		return
	}

	if debug {
		utils.LogDebug("attached child %d\n", pid)
	}


	syscall.Kill(pid, syscall.SIGCONT)

	go waitMonitor(pid,childrenWaits)

loop:
	for {
		select {
		case mysig := <-mySignals:
			isTerminated = handlingMySignal(pid,mysig)
			//go handlingMySignal(pid,mysig)

			if true == isTerminated {
				break loop
			}

		case result := <-childrenWaits:
			isTerminated2 = monitoringSyscall(pid,result)
			//go monitoringSyscall(pid,result)

			if true == isTerminated2 {
				break loop
			}
		} // endselect
	} // endloop
}

func init() {
	flag.BoolVar(&childMode, "child-mode", false, "Used to run the child mode to initiate tracing.")
	flag.StringVar(&policyFile, "policy", "[default]", "Path to policy config file. If set \"[default]\", it uses the embedded default policy.")
	flag.BoolVar(&debug, "debug", false, "Set the debug mode. Shows every detail of syscalls.")
	flag.BoolVar(&watch, "watch", false, "Set the watch mode. Shows syscalls blocked by the policy.")
	flag.BoolVar(&noop, "noop", false, "Set the no-op mode. Jail becomes a completely transparent exec wrapper.")
	// debug = true
	// watch = true
}

func handleExit() {
	if e := recover(); e != nil {
		color.Unset()
		// When log.Panic is used, recover() returns the printed string.
		if _, ok := e.(string); ok == true {
			os.Exit(1)
		}
		// When panic(Exit{N}) is used.
		if exit, ok := e.(Exit); ok == true {
			os.Exit(exit.Code)
		}
		// Otherwise bubble up.
		panic(e)
	}
}


func InitializeFilter() {
	arch, _ := seccomp.GetNativeArch()
	laterFilter, _ := seccomp.NewFilter(seccomp.ActErrno.SetReturnCode(int16(syscall.EPERM)))
	for _, syscallName := range policyInst.GetAllowedSyscalls() {
		syscallId, err := seccomp.GetSyscallFromNameByArch(syscallName, arch)
		if err == nil {
			laterFilter.AddRuleExact(syscallId, seccomp.ActAllow)
		}
	}
	for _, syscallName := range policyInst.GetTracedSyscalls() {
		syscallId, err := seccomp.GetSyscallFromNameByArch(syscallName, arch)
		if err == nil {
			//laterFilter.AddRuleExact(syscallId, seccomp.ActTrace)
			laterFilter.AddRuleExact(syscallId, seccomp.ActAllow)
		}
	}
	killSyscalls := []string{"kill", "killpg", "tkill", "tgkill"}
	for _, syscallName := range killSyscalls {
		scId, err := seccomp.GetSyscallFromNameByArch(syscallName, arch)
		if err == nil {
			// if not ActAllow child process not stopped :D
			//laterFilter.AddRuleExact(scId, seccomp.ActTrace)
			laterFilter.AddRuleExact(scId, seccomp.ActAllow)
		}
	}

	laterFilter.SetNoNewPrivsBit(true)
	// Now we have the working tracer parent.
	// Make kill() syscall to be traced as well for more sophisticated filtering.
	err := laterFilter.Load()
	if err != nil {
		utils.LogError("ScmpFilter.Load (2): ", err)
	}
	laterFilter.Release()
}

func ExecuteProcess() {
	// Replace myself with the language runtime.
	binaryPath, err := exec.LookPath(flag.Arg(0))
	if err != nil {
		utils.LogError("LookPath: %s", err)
	}
	err = syscall.Exec(binaryPath, flag.Args()[0:], os.Environ())

	// NOTE: "function not implemented" errors here may be due to above codes.
	utils.LogError("Exec(\"%s\"): %s\nNOTE: You need to provide the absolute path.", flag.Arg(0), err)
}

func SettingJailFlag() {

	flag.Parse()

	if noop {
		utils.LogDebug("NOOP MODE: doing nothing! (debug/watch are disabled, too)")
		debug = false
		watch = false
	} else {
		if debug {
			utils.LogDebug("DEBUG MODE: showing all details")
			watch = false
		}
		if watch {
			utils.LogDebug("WATCH MODE: all syscalls are ALLOWED but it shows which ones will be blocked by the current policy.")
		}
	}
}

func main() {
	var err error
	defer handleExit()

	syscall.Umask(0022)

	l := log.New(os.Stderr,"",0)

	SettingJailFlag()

	if !childMode {
		/* The parent. */

		if flag.NArg() < 1 {
			utils.LogError("Main: Not enough command-line arguments. See the docs.")
		}

		policyInst, err = policy.GeneratePolicyFromYAML(policyFile)
		if err != nil {
			utils.LogError("GeneratePolicy: %s",err)
		}

		/* Initialize fork/exec of the child. */

		runtime.GOMAXPROCS(1)
		runtime.LockOSThread()
		// Locking the OS thread is required to let syscall.Wait4() work correctly
		// because waitpid() only monitors the caller's direct children, not
		// siblings' children.
		args := append([]string{
			intraJailPath,
			"-child-mode",
			"-policy",
			policyInst.(policy.FileBasedPolicy).FileName,
		}, flag.Args()[0:]...)
		cwd, _ := os.Getwd()
		envs := utils.FilterEnvs(os.Environ(), policyInst.GetPreservedEnvKeys())
		envs = append(envs, policyInst.GetExtraEnvs()...)
		if debug {
			utils.LogEnv("Environment:",envs)
		}

		var pid int
		pid, err = syscall.ForkExec(args[0], args, &syscall.ProcAttr{
			cwd,
			envs,
			[]uintptr{0, 1, 2},
			&syscall.SysProcAttr{
				Ptrace: false, // should be disabled when using ptraceSeize
			},
		})

		if err != nil {
			utils.LogError("ForkExec(\"%s\"): %s", args[0], err)
		}

		if noop {
			var status syscall.WaitStatus
			syscall.Wait4(pid, &status, syscall.WALL, nil)
		} else {
			traceProcess(l, pid)
		}

	} else {
		/* The child. */

		// Waiting...
		// Inform the parent that I'm ready to continue.
		// Any code before this line code must use only non-traced system calls in
		// the filter because the tracer has not set up itself yet.
		// (traced syscalls will cause ENOSYS "function not implemented" error)
		syscall.Kill(os.Getpid(), syscall.SIGSTOP)

		// Wait amount of time until parent process ready to trace syscall.
		// It seems to be naive solution. But it works fine.

		if !noop {

			policyInst, err = policy.GeneratePolicyFromYAML(policyFile)
			if err != nil {
				utils.LogError("GeneratePolicy: %s", err)
			}

			InitializeFilter()
		}

		// NOTE: signal.Reset() here causes race conditions with the tracer.
		// (syscall tracing doesn't work deterministically with it.)
		ExecuteProcess()
	}
}
