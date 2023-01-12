use libc::c_void;
use libc::user_regs_struct;
use nix::errno::Errno;
use nix::unistd::Pid;

macro_rules! syscall_name {
    ($x:expr) => ($x.regs[8]);
}

macro_rules! syscall_arg1 {
    ($x:expr) => ($x.regs[0]);
}

macro_rules! syscall_arg2 {
    ($x:expr) => ($x.regs[1]);
}

macro_rules! syscall_arg3 {
    ($x:expr) => ($x.regs[2]);
}

macro_rules! syscall_ret {
    ($x:expr) => ($x.regs[0]);
}

pub fn getregs(pid: Pid) -> Result<user_regs_struct, Errno> {
    let mut data = std::mem::MaybeUninit::uninit();
    let iov = libc::iovec {
        iov_base: data.as_mut_ptr() as *mut c_void,
        iov_len: std::mem::size_of::<user_regs_struct>(),
    };
    let res = unsafe {
        libc::ptrace(
            libc::PTRACE_GETREGSET,
            libc::pid_t::from(pid),
            libc::NT_PRSTATUS,
            &iov as *const _ as *const c_void,
        )
    };
    Errno::result(res)?;
    Ok(unsafe { data.assume_init() })
}

pub fn setregs(pid: Pid, mut regs: user_regs_struct) -> Result<(), Errno> {
    let iov = libc::iovec {
        iov_base: &mut regs as *mut _ as *mut c_void,
        iov_len: std::mem::size_of::<user_regs_struct>(),
    };
    let res = unsafe {
        libc::ptrace(
            libc::PTRACE_SETREGSET,
            libc::pid_t::from(pid),
            libc::NT_PRSTATUS,
            &iov as *const _ as *const c_void,
        )
    };
    Errno::result(res).map(drop)
}
