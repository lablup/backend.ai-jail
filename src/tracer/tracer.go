package tracer

import (
	"syscall"
)

// Ref: https://github.com/torvalds/linux/blob/master/include/uapi/linux/ptrace.h

const PTRACE_SEIZE uintptr = 0x4206     // Linux >= 3.4
const PTRACE_INTERRUPT uintptr = 0x4207 // Linux >= 3.4
const PTRACE_LISTEN uintptr = 0x4208    // Linux >= 3.4
const PTRACE_EVENT_SECCOMP uint = 7
const PTRACE_EVENT_STOP uint = 128

const PTRACE_EVENT_CLONE uint = syscall.PTRACE_EVENT_CLONE
const PTRACE_EVENT_FORK uint = syscall.PTRACE_EVENT_FORK
const PTRACE_EVENT_VFORK uint = syscall.PTRACE_EVENT_VFORK
const PTRACE_EVENT_EXEC uint = syscall.PTRACE_EVENT_EXEC

const OurPtraceOpts int = (1 << PTRACE_EVENT_SECCOMP ) | // PTRACE_O_TRACESECCOMP
	(1 << 20 ) | // PTRACE_O_EXITKILL, Linux >= 3.4
	syscall.PTRACE_O_TRACECLONE |
	syscall.PTRACE_O_TRACEFORK |
	syscall.PTRACE_O_TRACEVFORK |
	syscall.PTRACE_O_TRACEEXEC


func PtraceAttach(pid int, opts int) (uintptr, error) {
	ret, _, err := syscall.Syscall6(syscall.SYS_PTRACE, syscall.PTRACE_ATTACH, uintptr(pid), 0, uintptr(opts), 0, 0)
	return ret, err
}

func PtraceSeize(pid int, opts int) (uintptr, error) {
	ret, _, err := syscall.Syscall6(syscall.SYS_PTRACE, PTRACE_SEIZE, uintptr(pid), 0, uintptr(opts), 0, 0)
	return ret, err
}

func PtraceInterrupt(pid int) (uintptr, error) {
	ret, _, err := syscall.Syscall6(syscall.SYS_PTRACE, PTRACE_INTERRUPT, uintptr(pid), 0, 0, 0, 0)
	return ret, err
}

func PtraceListen(pid int, sig int) (uintptr, error) {
	ret, _, err := syscall.Syscall6(syscall.SYS_PTRACE, PTRACE_LISTEN, uintptr(pid), 0, uintptr(sig), 0, 0)
	return ret, err
}

func PtraceCont(pid int, signal int) (err error) {
	return syscall.PtraceCont(pid,signal)
}

func PtraceGetRegs(pid int, regsout *syscall.PtraceRegs) (err error) {
	return syscall.PtraceGetRegs(pid, regsout)
}

func PtraceSetRegs(pid int, regs *syscall.PtraceRegs) (err error) {
	return syscall.PtraceSetRegs(pid, regs)
}

func PtraceGetEventMsg(pid int) (msg uint, err error) {
	return syscall.PtraceGetEventMsg(pid)
}
