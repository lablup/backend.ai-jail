package policy

import "fmt"

type PathOps int

const (
	OP_OPEN PathOps = iota
	OP_ACCESS
	OP_EXEC
	OP_STAT
	OP_CHMOD
)

var pathOpsNameMap map[string]PathOps

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

type PolicyConf struct {
	WhitelistPaths   map[PathOps][]string `yaml:"whitelist_paths"`
	ExecAllowance    int                  `yaml:"exec_allowance"`
	ForkAllowance    int                  `yaml:"fork_allowance"`
	MaxChildProcs    uint                 `yaml:"max_child_procs"`
	ExtraEnvs        []string             `yaml:"extra_envs"`
	PreservedEnvKeys []string             `yaml:"preserved_env_keys"`
	TracedSyscalls   []string             `yaml:"traced_syscalls"`
	AllowedSyscalls  []string             `yaml:"allowed_syscalls"`
}

var defaultConf PolicyConf

// References when you are going to update this file:
//  - https://github.com/docker/docker/blob/master/docs/security/seccomp.md
//  - https://filippo.io/linux-syscall-table/

func init() {
	pathOpsNameMap = map[string]PathOps{
		"OP_OPEN":   OP_OPEN,
		"OP_ACCESS": OP_ACCESS,
		"OP_EXEC":   OP_EXEC,
		"OP_STAT":   OP_STAT,
		"OP_CHMOD":  OP_CHMOD,
	}
	defaultConf.WhitelistPaths = map[PathOps][]string{
		OP_OPEN:   []string{},
		OP_ACCESS: []string{},
		OP_EXEC:   []string{},
		OP_STAT:   []string{},
		OP_CHMOD:  []string{"/home/work/", "/tmp/"},
	}
	defaultConf.ExecAllowance = 0
	defaultConf.ForkAllowance = -1
	defaultConf.MaxChildProcs = 32
	defaultConf.ExtraEnvs = []string{}
	defaultConf.PreservedEnvKeys = []string{
		"HOME", "PATH", "LANG",
		"PYENV_ROOT", "PYTHONPATH",
		"LD_PRELOAD",
	}
	//// Following syscalls are intercepted by our ptrace-based tracer.
	//// The tracer will implement its own policies, optionally by inspecting
	//// the arguments in the registers.
	defaultConf.TracedSyscalls = []string{
		// 1st param is filename/path
		"stat",
		"lstat",
		"statfs",
		"getxattr",
		"lgetxattr",
		"readlink",
		"unlink",
		"rmdir",
		"truncate",
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
		// traced by ptrace exec/fork/clone
		"fork",
		"vfork",
		"clone",
		"execve",
		// "kill" will be added by intra-jail
	}

	// Following syscalls are blindly allowed.
	// IMPORTANT: ptrace MUST NOT be included!
	defaultConf.AllowedSyscalls = []string{
		// blindly allowed
		"read",
		"readv",
		"preadv",
		"pread64",
		"readahead",
		"recv",
		"recvfrom",
		"recvmsg",
		"recvmmsg",
		"write",
		"writev",
		"pwritev",
		"pwrite64",
		"sendfile",
		"sendfile64",
		"sendto",
		"sendmsg",
		"sendmmsg",
		"close",
		"fallocate",
		"fstat",
		"fstatfs",
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
		"memfd_create",
		"ftruncate",
		"utimensat",
		"futimens",
		"utime",
		"utimes",
		"tee",
		"splice",
		"vmsplice",
		"tkill",
		"tgkill",
		"io_cancel",
		"io_destroy",
		"io_getevents",
		"ioprio_get",
		"ioprio_set",
		"io_setup",
		"io_submit",
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
		"gettid",
		"getuid",
		"setuid", // for shell
		"geteuid",
		"getreuid",
		"getresuid",
		"getgid",
		"setgid", // for shell
		"getegid",
		"getregid",
		"getresgid",
		"getgroups", // for shell
		"getcwd",
		"socket",
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
		"exit",
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
	}
}

// vim: ts=4 sts=4 sw=4 noet
