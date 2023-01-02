use crate::vec_of_strings;

use derive_more::From;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub trait SandboxPolicy {
    fn check_path_op(&self, path: &str, op: PathOps, mode: i32) -> bool;
    fn get_exec_allowance(&self) -> i32;
    fn get_fork_allowance(&self) -> i32;
    fn get_max_child_procs(&self) -> i32;
    fn get_extra_envs(&self) -> Vec<String>;
    fn get_preserved_env_keys(&self) -> Vec<String>;
    fn get_traced_syscalls(&self) -> Vec<String>;
    fn get_allowed_syscalls(&self) -> Vec<String>;
}

#[derive(From, Debug)]
pub enum PolicyError {
    YamlParseError(serde_yaml::Error),
    IOError(std::io::Error),
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct PolicyConf {
    pub diff_to_default: bool,
    pub whitelist_paths: HashMap<PathOps, Vec<String>>,
    pub exec_allowance: i32,
    pub fork_allowance: i32,
    pub max_child_procs: i32,
    pub extra_envs: Vec<String>,
    pub preserved_env_keys: Vec<String>,
    pub traced_syscalls: Vec<String>,
    pub allowed_syscalls: Vec<String>,
}

#[derive(Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum PathOps {
    OpOpen = 1,
    OpAccess = 2,
    OpExec = 3,
    OpStat = 4,
    OpChmod = 5,
}

impl Default for PolicyConf {
    fn default() -> Self {
        let mut whitelist_paths: HashMap<PathOps, Vec<String>> = HashMap::new();
        whitelist_paths.insert(PathOps::OpOpen, vec_of_strings!["*"]);
        whitelist_paths.insert(PathOps::OpAccess, vec_of_strings!["*"]);
        whitelist_paths.insert(PathOps::OpExec, vec_of_strings!["*"]);
        whitelist_paths.insert(PathOps::OpStat, vec_of_strings!["*"]);
        whitelist_paths.insert(PathOps::OpChmod, vec_of_strings!["/home/work/*", "/tmp/*"]);
        PolicyConf {
            diff_to_default: false,
            exec_allowance: 0,
            fork_allowance: -1,
            max_child_procs: 512,
            extra_envs: Vec::new(),
            whitelist_paths,
            preserved_env_keys: vec_of_strings![
                "HOME",
                "PATH",
                "LANG",
                "PYENV_ROOT",
                "PYTHONPATH",
                "LD_LIBRARY_PATH",
                "LD_PRELOAD"
            ],
            traced_syscalls: vec_of_strings![
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
                //"execve",
                "clone",
                "clone3" // "kill"-related syscalls will be added by children
            ],
            allowed_syscalls: vec_of_strings![
                "_sysctl",
                "accept",
                "accept4",
                "acct",
                "add_key",
                "adjtimex",
                "afs_syscall",
                "alarm",
                "arch_prctl",
                "bind",
                "bpf",
                "brk",
                "capget",
                "capset",
                "chdir",
                "chown",
                "chroot",
                "clock_adjtime",
                "clock_getres",
                "clock_gettime",
                "clock_nanosleep",
                "clock_settime",
                "close",
                "connect",
                "copy_file_range",
                "create_module",
                "delete_module",
                "dup",
                "dup2",
                "dup3",
                "epoll_create",
                "epoll_create1",
                "epoll_ctl",
                "epoll_ctl_old",
                "epoll_pwait",
                "epoll_wait",
                "epoll_wait_old",
                "eventfd",
                "eventfd2",
                "execve",
                "execveat",
                "exit",
                "exit_group",
                "faccessat2",
                "fadvise64",
                "fallocate",
                "fanotify_init",
                "fanotify_mark",
                "fchdir",
                "fchmod",
                "fchown",
                "fchownat",
                "fcntl",
                "fdatasync",
                "fgetxattr",
                "finit_module",
                "flistxattr",
                "flock",
                "fremovexattr",
                "fsconfig",
                "fsetxattr",
                "fsmount",
                "fsopen",
                "fspick",
                "fstat",
                "fstatfs",
                "fsync",
                "ftruncate",
                "futex",
                "futimesat",
                "get_kernel_syms",
                "get_mempolicy",
                "get_robust_list",
                "get_thread_area",
                "getcpu",
                "getcwd",
                "getdents",
                "getdents64",
                "getegid",
                "geteuid",
                "getgid",
                "getgroups",
                "getitimer",
                "getpeername",
                "getpgid",
                "getpgrp",
                "getpid",
                "getpmsg",
                "getppid",
                "getpriority",
                "getrandom",
                "getresgid",
                "getresuid",
                "getrlimit",
                "getrusage",
                "getsid",
                "getsockname",
                "getsockopt",
                "gettid",
                "gettimeofday",
                "getuid",
                "getxattr",
                "init_module",
                "inotify_add_watch",
                "inotify_init",
                "inotify_init1",
                "inotify_rm_watch",
                "io_cancel",
                "io_destroy",
                "io_getevents",
                "io_pgetevents",
                "io_setup",
                "io_submit",
                "io_uring_enter",
                "io_uring_register",
                "io_uring_setup",
                "ioctl",
                "ioperm",
                "iopl",
                "ioprio_get",
                "ioprio_set",
                "kcmp",
                "kexec_file_load",
                "kexec_load",
                "keyctl",
                "kill",
                "lchown",
                "lgetxattr",
                "listen",
                "listxattr",
                "llistxattr",
                "lookup_dcookie",
                "lremovexattr",
                "lseek",
                "lsetxattr",
                "madvise",
                "mbind",
                "membarrier",
                "memfd_create",
                "migrate_pages",
                "mincore",
                "mlock",
                "mlock2",
                "mlockall",
                "mmap",
                "modify_ldt",
                "mount",
                "move_mount",
                "move_pages",
                "mprotect",
                "mq_getsetattr",
                "mq_notify",
                "mq_open",
                "mq_timedreceive",
                "mq_timedsend",
                "mq_unlink",
                "mremap",
                "msgctl",
                "msgget",
                "msgrcv",
                "msgsnd",
                "msync",
                "munlock",
                "munlockall",
                "munmap",
                "name_to_handle_at",
                "nanosleep",
                "newfstatat",
                "nfsservctl",
                "open_by_handle_at",
                "open_tree",
                "openat2",
                "pause",
                "perf_event_open",
                "personality",
                "pidfd_getfd",
                "pidfd_open",
                "pidfd_send_signal",
                "pipe",
                "pipe2",
                "pivot_root",
                "pkey_alloc",
                "pkey_free",
                "pkey_mprotect",
                "poll",
                "ppoll",
                "prctl",
                "pread64",
                "preadv",
                "preadv2",
                "prlimit64",
                "process_vm_readv",
                "process_vm_writev",
                "pselect6",
                "ptrace",
                "putpmsg",
                "pwrite64",
                "pwritev",
                "pwritev2",
                "query_module",
                "quotactl",
                "read",
                "readahead",
                "readv",
                "reboot",
                "recvfrom",
                "recvmmsg",
                "recvmsg",
                "remap_file_pages",
                "removexattr",
                "renameat2",
                "request_key",
                "restart_syscall",
                "rseq",
                "rt_sigaction",
                "rt_sigpending",
                "rt_sigprocmask",
                "rt_sigqueueinfo",
                "rt_sigreturn",
                "rt_sigsuspend",
                "rt_sigtimedwait",
                "rt_tgsigqueueinfo",
                "sched_get_priority_max",
                "sched_get_priority_min",
                "sched_getaffinity",
                "sched_getattr",
                "sched_getparam",
                "sched_getscheduler",
                "sched_rr_get_interval",
                "sched_setaffinity",
                "sched_setattr",
                "sched_setparam",
                "sched_setscheduler",
                "sched_yield",
                "seccomp",
                "security",
                "select",
                "semctl",
                "semget",
                "semop",
                "semtimedop",
                "sendfile",
                "sendmmsg",
                "sendmsg",
                "sendto",
                "set_mempolicy",
                "set_robust_list",
                "set_thread_area",
                "set_tid_address",
                "setdomainname",
                "setfsgid",
                "setfsuid",
                "setgid",
                "setgroups",
                "sethostname",
                "setitimer",
                "setns",
                "setpgid",
                "setpriority",
                "setregid",
                "setresgid",
                "setresuid",
                "setreuid",
                "setrlimit",
                "setsid",
                "setsockopt",
                "settimeofday",
                "setuid",
                "setxattr",
                "shmat",
                "shmctl",
                "shmdt",
                "shmget",
                "shutdown",
                "sigaltstack",
                "signalfd",
                "signalfd4",
                "socket",
                "socketpair",
                "splice",
                "statx",
                "swapoff",
                "swapon",
                "sync",
                "sync_file_range",
                "syncfs",
                "sysfs",
                "sysinfo",
                "syslog",
                "tee",
                "tgkill",
                "time",
                "timer_create",
                "timer_delete",
                "timer_getoverrun",
                "timer_gettime",
                "timer_settime",
                "timerfd_create",
                "timerfd_gettime",
                "timerfd_settime",
                "times",
                "tkill",
                "tuxcall",
                "umask",
                "umount2",
                "uname",
                "unshare",
                "uselib",
                "userfaultfd",
                "ustat",
                "utime",
                "utimensat",
                "utimes",
                "vhangup",
                "vmsplice",
                "vserver",
                "wait4",
                "waitid",
                "write",
                "writev"
            ],
        }
    }
}
