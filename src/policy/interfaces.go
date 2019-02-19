package policy

import (
	glob "github.com/gobwas/glob"
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
	defaultConf.WhitelistPaths = map[PathOps][]PatternMatcher{
		OP_OPEN:   []PatternMatcher{
			PatternMatcher{glob.MustCompile("*")},
		},
		OP_ACCESS: []PatternMatcher{
			PatternMatcher{glob.MustCompile("*")},
		},
		OP_EXEC: []PatternMatcher{
			PatternMatcher{glob.MustCompile("*")},
		},
		OP_STAT: []PatternMatcher{
			PatternMatcher{glob.MustCompile("*")},
		},
		OP_CHMOD: []PatternMatcher{
			PatternMatcher{glob.MustCompile("/home/work/*")},
			PatternMatcher{glob.MustCompile("/tmp/*")},
		},
	}
	defaultConf.ExecAllowance = 0
	defaultConf.ForkAllowance = -1
	defaultConf.MaxChildProcs = 32
	defaultConf.ExtraEnvs = []string{}
	defaultConf.PreservedEnvKeys = []string{
		"HOME", "PATH", "LANG",
		"PYENV_ROOT", "PYTHONPATH",
		"LD_LIBRARY_PATH",
		"LD_PRELOAD",
	}
	//// Following syscalls are intercepted by our ptrace-based tracer.
	//// The tracer will implement its own policies, optionally by inspecting
	//// the arguments in the registers.
	defaultConf.TracedSyscalls = []string{
		// 1st param is filename/path
		"stat",
		"lstat",
		"lstat64",
		"statfs",
		"readlink",
		"unlink",
		"rmdir",
		"truncate",
		"truncate64",
		"access", // 2nd param is mode
		"creat",  // 2nd param is mode
		"mkdir",  // 2nd param is mode
		"mknod",  // 2nd param is mode
		"chmod",  // 2nd param is mode
		"open",   // 3rd param is mode
		// 2nd param is filename/path
		"readlinkat",
		"unlinkat",
		"fchmodat",  // 3rd param is mode
		"faccessat", // 3rd param is mode
		"mkdirat",   // 3rd param is mode
		"mknodat",   // 3rd param is mode
		"openat",    // 4th param is mode
		// 1st & 2nd params are filename/paths
		"link",
		"rename",
		// 1st & 3rd params are filename/paths
		"symlink",
		"symlinkat",
		// 2nd & 4th params are filename/paths
		"renameat",
		"linkat",
		// traced by ptrace exec/fork/clone
		"fork",
		"vfork",
		"clone",
		"execve",
		// "kill"-related syscalls will be added by children
	}

	// Following syscalls are white-listed.
	// IMPORTANT: ptrace MUST NOT be included!
	defaultConf.AllowedSyscalls = []string{
		"execve",
		"execveat",
		// blindly allowed
		"prlimit64",
		"read",
		"readv",
		"preadv",
		"preadv2",
		"pread64",
		"readahead",
		"recv",
		"recvfrom",
		"recvmsg",
		"recvmmsg",
		"write",
		"writev",
		"pwritev",
		"pwritev2",
		"pwrite64",
		"sendfile",
		"sendfile64",
		"sendto",
		"sendmsg",
		"sendmmsg",
		"close",
		"fallocate",
		"fchmod",
		"fstat",
		"newfstatat",
		"fstatfs",
		"umask",
		"mmap",
		"mremap",
		"mprotect",
		"munmap",
		"mbind",
		"mlock",
		"mlock2",
		"munlock",
		"mlockall",
		"munlockall",
		"brk",
		"lseek",
		"_llseek",
		"getdents",
		"getdents64",
		"alarm",
		"dup",
		"dup2",
		"dup3",
		"chdir",
		"fchdir",
		"flock",
		"fsync",
		"fdatasync",
		"msync",
		"sync",
		"syncfs",
		"sync_file_range",
		"memfd_create",
		"ftruncate",
		"utimensat",
		"futimens",
		"futimesat",
		"time",
		"utime",
		"utimes",
		"tee",
		"splice",
		"vmsplice",
		"io_cancel",
		"io_destroy",
		"io_getevents",
		"ioprio_get",
		"ioprio_set",
		"io_setup",
		"io_submit",
		"copy_file_range",
		"remap_file_pages",
		"ipc",
		"mq_getsetattr",
		"mq_notify",
		"mq_open",
		"mq_timedreceive",
		"mq_timedsend",
		"mq_unlink",
		"rt_sigaction",
		"rt_sigprocmask",
		"rt_sigreturn",
		"rt_sigpending",
		"rt_sigtimedwait",
		"rt_sigsuspend",
		"rt_sigqueueinfo",
		"rt_tgsigqueueinfo",
		"signal",
		"sigaltstack",
		"sigpending",
		"sigprocmask",
		"sigsuspend",
		"sigreturn",
		"restart_syscall",
		"semctl",
		"semget",
		"semop",
		"semtimedop",
		"shmget",
		"shmat",
		"shmctl",
		"shmdt",
		"shmget",
		"msgget",
		"msgsnd",
		"msgrcv",
		"msgctl",
		"mincore",
		"fadvise64",
		"madvise",
		"arch_prctl",
		"prctl",
		"getrlimit",
		"ugetrlimit",
		"set_tid_address",
		"clear_tid_address",
		"set_thread_area",
		"get_thread_area",
		"set_robust_list",
		"get_robust_list",
		"futex",
		"sched_getaffinity",
		"sched_setaffinity",
		"sched_getparam",
		"sched_getattr",
		"sched_getscheduler",
		"sched_setscheduler",
		"sched_get_priority_max",
		"sched_get_priority_min",
		"sched_rr_get_interval",
		"sched_yield",
		"getpriority",
		"getcpu",
		"eventfd",
		"eventfd2",
		"signalfd",
		"signalfd4",
		"timerfd_create",
		"timerfd_settime",
		"timerfd_gettime",
		"setsockopt",
		"getsockopt",
		"getsockname",
		"getpeername",
		"bind",
		"listen",
		"setpriority",
		"gettid",
		"getuid",
		"setuid", // for shell
		"geteuid",
		"getreuid",
		"getresuid",
		"getgid",
		"getgid32",
		"setgid", // for shell
		"setgid32",
		"getegid",
		"getegid32",
		"setregid",
		"setregid32",
		"setresuid",
		"setresuid32",
		"setresgid",
		"setresgid32",
		"getresuid",
		"getresuid32",
		"getresgid",
		"getresgid32",
		"setfsuid",
		"setfsuid32",
		"setfsgid",
		"setfsgid32",
		"setgroups",
		"setgroups32",
		"getgroups", // for shell
		"getgroups32",
		"getcwd",
		"socket",
		"socketcall",
		"socketpair",
		"connect",
		"accept",
		"accept4",
		"shutdown",
		"pipe",
		"pipe2",
		"ioctl",
		"fcntl",
		"inotify_init",
		"inotify1_init",
		"inotify_add_watch",
		"inotify_rm_watch",
		"select",
		"pselect",
		"pselect6",
		"_newselect",
		"pause",
		"poll",
		"ppoll",
		"epoll_create",
		"epoll_create1",
		"epoll_wait",
		"epoll_pwait",
		"epoll_ctl",
		"fanotify_mark",
		"inotify_add_watch",
		"inotify_init",
		"inotify_init1",
		"inotify_rm_watch",
		"_exit",
		"exit_group",
		"wait",
		"wait3",
		"wait4",
		"waitid",
		"waitpid",
		"uname",
		"getrandom",
		"timer_create",
		"timer_settime",
		"timer_gettime",
		"timer_getoverrun",
		"timer_delete",
		"nanosleep",
		"capget",
		"capset",
		"syslog",
		"sysinfo",
		// potentially replaced with VDSO
		"getpid",
		"getppid",
		"getpgid",
		"setpgid", // for shell
		"getpgrp",
		"getsid",
		"setsid", // for shell
		"gettimeofday",
		"clock_gettime",
		"clock_getres",
		"clock_nanosleep",
		"modify_ldt",
		"lchown",
		"lchown32",
		"listxattr",
		"removexattr",
		"getxattr",
		"setxattr",
		"llistxattr",
		"lremovexattr",
		"lgetxattr",
		"lsetxattr",
		"flistxattr",
		"fremovexattr",
		"fgetxattr",
		"fsetxattr",
		"seccomp",
		"statx",
		"adjtimex",
		"clone",
	}
}
