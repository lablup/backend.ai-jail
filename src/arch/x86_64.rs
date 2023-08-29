use libc::user_regs_struct;
use nix::errno::Errno;
use nix::sys::ptrace;
use nix::unistd::Pid;

macro_rules! syscall_name {
    ($x:expr) => {
        $x.orig_rax
    };
}

macro_rules! syscall_arg1 {
    ($x:expr) => {
        $x.rdi
    };
}

macro_rules! syscall_arg2 {
    ($x:expr) => {
        $x.rsi
    };
}

macro_rules! syscall_arg3 {
    ($x:expr) => {
        $x.rdx
    };
}

macro_rules! syscall_ret {
    ($x:expr) => {
        $x.rax
    };
}

pub fn getregs(pid: Pid) -> Result<user_regs_struct, Errno> {
    ptrace::getregs(pid)
}

pub fn setregs(pid: Pid, regs: user_regs_struct) -> Result<(), Errno> {
    ptrace::setregs(pid, regs)
}
