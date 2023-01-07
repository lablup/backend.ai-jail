use crate::interface::{Args, HookType, PluginInterface, SyscallHook};
use crate::policy::filebased::FileBasedPolicy;
use crate::policy::traits::{PathOps, SandboxPolicy};
use crate::{panic_if_err, utils};
use libc::{c_int, c_uint, c_void};
use libseccomp::{ScmpAction, ScmpArch, ScmpFilterContext, ScmpSyscall};
use log::{debug, error, info, warn};
use nix::errno::Errno;
use nix::sys::wait::{wait, waitpid, WaitPidFlag, WaitStatus};
use nix::sys::{
    ptrace, ptrace::Options as PtraceOptions, signal::signal, signal::SigHandler, signal::Signal,
};
use nix::unistd::{fork, ForkResult, Pid};
use std::collections::{HashMap, HashSet};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{exit, id as getpid, Command};
use std::{env, fs};
use tokio::signal::unix::{signal as tokioSignal, SignalKind};

pub struct Jail {
    policy_inst: FileBasedPolicy,
    cli: Args,
    execution_mode: JailExecutionMode,
    exec_count: i32,
    fork_count: i32,
    child_count: i32,
    max_child_count: i32,
    plugins: HashMap<String, Box<dyn PluginInterface>>,
    libraries: HashMap<String, libloading::Library>,
    pre_execution_hooks: HashMap<String, Vec<String>>,
    post_execution_hooks: HashMap<String, Vec<String>>,
}

enum JailExecutionMode {
    PARENT,
    CHILD,
}

#[derive(Debug, Clone)]
struct WaitResult {
    status: WaitStatus,
    status_raw: i32,
    result: i32,
}

#[cfg(target_arch = "x86_64")]
macro_rules! syscall_name {
    ( $x:expr ) => {
        $x.orig_rax
    };
}
#[cfg(target_arch = "x86_64")]
macro_rules! syscall_arg1 {
    ( $x:expr ) => {
        $x.rdi
    };
}
#[cfg(target_arch = "x86_64")]
macro_rules! syscall_arg2 {
    ( $x:expr ) => {
        $x.rsi
    };
}
#[cfg(target_arch = "x86_64")]
macro_rules! syscall_arg3 {
    ( $x:expr ) => {
        $x.rdx
    };
}
#[cfg(target_arch = "x86_64")]
macro_rules! syscall_arg4 {
    ( $x:expr ) => {
        $x.rcx
    };
}
#[cfg(target_arch = "x86_64")]
macro_rules! syscall_arg5 {
    ( $x:expr ) => {
        $x.r8d
    };
}
#[cfg(target_arch = "x86_64")]
macro_rules! syscall_arg6 {
    ( $x:expr ) => {
        $x.r9d
    };
}
/// Wrapper of waitpid()
///
/// # Arguments
/// * `pid` - target PID to wait for. if `None`, this will wait for any child process (same with behavior of waitpid()'s -1 pid).
/// * `option` - waitpid() option
fn wait_for_status<P: Into<Option<Pid>>>(
    pid: P,
    options: Option<WaitPidFlag>,
) -> Result<WaitResult, Errno> {
    let mut status: i32 = 0;
    let option_bits = match options {
        Some(bits) => bits.bits(),
        None => 0,
    };

    let res = unsafe {
        libc::waitpid(
            pid.into().unwrap_or_else(|| Pid::from_raw(-1)).into(),
            &mut status as *mut c_int,
            option_bits,
        )
    };

    match Errno::result(res)? {
        0 => Ok(WaitResult {
            status: WaitStatus::StillAlive,
            status_raw: status,
            result: 0,
        }),
        res => Ok(WaitResult {
            status: WaitStatus::from_raw(Pid::from_raw(res), status)?,
            status_raw: status,
            result: res,
        }),
    }
}

impl Jail {
    pub fn new(cli: Args) -> Jail {
        let policy_inst = panic_if_err!(FileBasedPolicy::generate_from_yaml(&cli.policy));
        let mut jail = Jail {
            policy_inst,
            cli,
            execution_mode: JailExecutionMode::PARENT,
            exec_count: 0,
            fork_count: 0,
            child_count: 1,
            max_child_count: 0,
            plugins: HashMap::new(),
            libraries: HashMap::new(),
            pre_execution_hooks: HashMap::new(),
            post_execution_hooks: HashMap::new(),
        };
        jail.load_plugins();
        jail
    }
}

impl Jail {
    /// Acts as an entrypoint for jail logic
    /// Attempt to fork process. If it's done, loads seccomp profile and starts requested command on child,
    /// and starts tracing child on parent process.
    pub fn run_tracer(&mut self) {
        if self.cli.args.len() < 1 {
            error!("Not enough command-line arguments. See the docs.");
            exit(1);
        }

        match unsafe { fork() } {
            Ok(ForkResult::Child) => {
                let mut preserved_env_keys = self.policy_inst.get_preserved_env_keys();
                let mut extra_envs = self.policy_inst.get_extra_envs();
                let mut envs = utils::filter_envs(&mut preserved_env_keys);
                envs.append(&mut extra_envs);

                debug!("Environment: {:?}", envs);

                for (key, _) in env::vars() {
                    env::remove_var(key);
                }

                for env in envs {
                    let split: Vec<&str> = env.split('=').collect();
                    env::set_var(split[0], split[1]);
                }

                // ptrace child process (if noop is set to false) and run exec()
                debug!("tracee: starting program");
                self.execution_mode = JailExecutionMode::CHILD;
                self.run_child();
            }

            Ok(ForkResult::Parent { child }) => {
                if self.cli.noop {
                    wait().unwrap();
                } else {
                    debug!("tracer: tracing {:?}", child);
                    self.trace_process(child);
                    debug!("Trace done");
                }
            }

            Err(err) => {
                panic!("[main] fork() failed: {}", err);
            }
        }
    }

    /// Loads external jail plugins packed as a shared library
    /// Tries to load .so files from ["/etc/backend.ai/jail/plugins/*.so", "/opt/jail/plugins/*.so", "./*.so"].
    /// Check out `interface::PluginInterface` for more information about plugin interface.
    fn load_plugins(&mut self) {
        for glob_path in [
            "/etc/backend.ai/jail/plugins/*.so",
            "/opt/jail/plugins/*.so",
            "./*.so",
        ] {
            for entry in glob::glob(glob_path).unwrap() {
                let path = panic_if_err!(entry);
                debug!("Trying to load plugin {:?}", path);
                match self.load_plugin(&path) {
                    Ok((p, l)) => {
                        debug!("Loaded plugin {:?}", &path);
                        let mut hooked_syscalls: Vec<SyscallHook> = Vec::new();
                        p.get_hooked_syscalls(&mut hooked_syscalls);
                        let plugin_name = p.get_name();
                        for syscall in &hooked_syscalls {
                            if syscall.hook_type == HookType::PRE
                                || syscall.hook_type == HookType::BOTH
                            {
                                let mut hook: Vec<String>;
                                if self.pre_execution_hooks.contains_key(&syscall.name) {
                                    hook = self.pre_execution_hooks.remove(&syscall.name).unwrap();
                                    hook.push(plugin_name.to_string());
                                } else {
                                    hook = Vec::new();
                                    hook.push(plugin_name.to_string());
                                }
                                self.pre_execution_hooks
                                    .insert(syscall.name.to_string(), hook);
                            }
                            if syscall.hook_type == HookType::POST
                                || syscall.hook_type == HookType::BOTH
                            {
                                let mut hook: Vec<String>;
                                if self.post_execution_hooks.contains_key(&syscall.name) {
                                    hook = self.post_execution_hooks.remove(&syscall.name).unwrap();
                                    hook.push(plugin_name.to_string());
                                } else {
                                    hook = Vec::new();
                                    hook.push(plugin_name.to_string());
                                }
                                self.post_execution_hooks
                                    .insert(syscall.name.to_string(), hook);
                            }
                        }
                        self.plugins.insert(plugin_name.to_string(), p);
                        self.libraries.insert(plugin_name.to_string(), l);
                    }
                    Err(e) => {
                        warn!(
                            "error while loading plugin {:?}: {}, skipping plugin import",
                            path,
                            e.to_string()
                        );
                    }
                }
            }
        }
    }

    fn load_plugin(
        &self,
        path: &PathBuf,
    ) -> Result<(Box<dyn PluginInterface>, libloading::Library), libloading::Error> {
        let lib = unsafe {
            match fs::read_link(path) {
                Ok(actual_path) => libloading::Library::new(actual_path),
                Err(_) => libloading::Library::new(path),
            }
        }?;
        let constructor: libloading::Symbol<fn() -> *mut dyn PluginInterface> =
            unsafe { lib.get(b"load") }?;
        let boxed_raw = constructor();
        let plugin = unsafe { Box::from_raw(boxed_raw) };

        // https://users.rust-lang.org/t/libloading-segfault/56848/4
        Ok((plugin, lib)) // we need to maintain ownership of lib object, otherwise it'll be dlclose()-ed
    }

    /// Trace lifecycle and syscall usage of child processes
    fn trace_process(&mut self, child: Pid) {
        let child_pid = child.clone().as_raw();

        unsafe {
            // panic_if_err!(signal(Signal::SIGSTOP, SigHandler::SigIgn));
            panic_if_err!(signal(Signal::SIGTTOU, SigHandler::SigIgn));
            panic_if_err!(signal(Signal::SIGTTIN, SigHandler::SigIgn));
            panic_if_err!(signal(Signal::SIGTSTP, SigHandler::SigIgn));
        }

        // Wait until child notifies parent that he is ready to be traced. When it's ready, child will send SIGSTOP.
        debug!("Waiting for child to stop");
        let wait_status = panic_if_err!(wait_for_status(child, Some(WaitPidFlag::WSTOPPED)));
        debug!("Child stopped");
        match wait_status.status {
            WaitStatus::Stopped(_, signal) if signal != Signal::SIGSTOP => {
                debug!("Unexpected wait status 0x{:8x}", wait_status.status_raw);
                return;
            }
            _ => {}
        }

        // Must specify PTRACE_O_TRACE{CLONE,FORK,VFORK} in order to trace every grandchildren spawned by children
        let ptrace_options = PtraceOptions::PTRACE_O_TRACESECCOMP
            | PtraceOptions::PTRACE_O_EXITKILL
            | PtraceOptions::PTRACE_O_TRACECLONE
            | PtraceOptions::PTRACE_O_TRACEFORK
            | PtraceOptions::PTRACE_O_TRACEVFORK;

        // Trace child with ptrace(PTRACE_SEIZE)
        match ptrace::seize(child, ptrace_options) {
            Err(e) => {
                debug!("ptrace_seize error: {:?}", e);
                return;
            }
            _ => {}
        }
        unsafe { libc::kill(child.as_raw(), libc::SIGCONT) };
        // since we're now attached to child using PTRACE, we need to send PTRACE_LISTEN to continue process
        unsafe {
            libc::ptrace(
                libc::PTRACE_LISTEN,
                child.as_raw() as *mut c_uint,
                std::ptr::null() as *const c_void,
                std::ptr::null() as *const c_void,
            )
        };

        debug!("attached to child {}", child);

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut int_signal = panic_if_err!(tokioSignal(SignalKind::interrupt()));
            let mut stop_signal = panic_if_err!(tokioSignal(SignalKind::terminate()));

            loop {
                tokio::select! {
                    // Parent received stop signal. Kill all children.
                    _ = int_signal.recv() => {
                        unsafe {
                            let pgid = libc::getpgid(child_pid.clone());
                            libc::kill(pgid, libc::SIGKILL);
                        };
                        panic_if_err!(waitpid(child.clone(), Some(WaitPidFlag::__WALL)));
                        break;
                    },
                    _ = stop_signal.recv() => {
                        unsafe {
                            let pgid = libc::getpgid(child_pid.clone());
                            libc::kill(pgid, libc::SIGKILL);
                        };
                        panic_if_err!(waitpid(child.clone(), Some(WaitPidFlag::__WALL)));
                        break;
                    }
                    // When one of the children's state changes
                    v = tokio::task::spawn_blocking(|| wait_for_status(None, None)) => {
                        let result = v.unwrap().unwrap();
                        match result.status {
                            // when child has exited
                            WaitStatus::Exited(pid, code) => {
                                debug!("EXIT (pid {:?}) status {:?}", pid, code);
                                match result.status.pid() {
                                    Some(p) => {
                                        if p == child {
                                            debug!("Our very child has exited. Done.");
                                            if self.cli.watch {
                                                info!("Max child count: {}.", self.policy_inst.get_max_child_procs());
                                            }
                                            // last remaining child has exited, so we don't have reason to survive.
                                            exit(0);
                                        } else {
                                            self.child_count -= 1;
                                            debug!("childCount is now {}", self.child_count);
                                        }
                                    },
                                    None => {}
                                }
                            },
                            // cause of state change is somewhat related to PTRACE
                            WaitStatus::PtraceEvent(pid, signal, evt_type) => {
                                match self.handle_ptrace_event(child, pid, signal, evt_type) {
                                    Ok(_) => continue,
                                    Err(e) => {
                                        error!("ptrace-continue error {:?}", e);
                                        match e {
                                            Errno::EBUSY | Errno::EFAULT | Errno::ESRCH => break,
                                            _ => continue,
                                        }
                                    }
                                }
                            },
                            // just for safety
                            WaitStatus::Stopped(pid, signal) => {
                                debug!("STOP (pid {:?}) signal {:?}", pid, signal);
                                let evt_type = result.status_raw >> 16;  // translate waitpid()'s status value to PTRACE_EVENT_ type
                                match self.handle_ptrace_event(child, pid, signal, evt_type) {
                                    Ok(_) => continue,
                                    Err(e) => {
                                        error!("ptrace-continue error {:?}", e);
                                        match e {
                                            Errno::EBUSY | Errno::EFAULT | Errno::ESRCH => break,
                                            _ => continue,
                                        }
                                    }
                                }
                            }
                            _ => continue
                        }
                    }
                }
            }
            debug!("out of loop");
        });
        debug!("out of async");
        return;
    }

    /// Handle ptrace event propagated from child.
    ///
    /// * Arguments
    ///
    /// - `child`: PID of our very first child (the one we fork()ed)
    /// - `target`: PID of process who actually created the event
    /// - `signal`: signal
    /// - `evt_num`: raw value of PTRACE_EVENT type. This will be translated to ptrace::Event enum value.
    fn handle_ptrace_event(
        &mut self,
        child: Pid,
        target: Pid,
        signal: Signal,
        evt_num: libc::c_int,
    ) -> Result<(), Errno> {
        let mut child_stopped = false;
        let mut signal_to_child: Option<Signal> = None;
        // convert raw int to ptrace::Event enum.
        let evt_type: ptrace::Event = unsafe { std::mem::transmute(evt_num) };
        debug!("PID {} => ptrace event: {:?}", target.as_raw(), evt_type);

        // check out Group-stop section of man ptrace(2)
        if evt_type == ptrace::Event::PTRACE_EVENT_STOP {
            child_stopped = true;
            debug!("group-stop detected");
        }

        match signal {
            Signal::SIGTRAP => {
                match evt_type {
                    // seccomp detected usage of traced system call
                    ptrace::Event::PTRACE_EVENT_SECCOMP => {
                        let mut extra_info: String = "".to_string();
                        let mut allow: bool;

                        // access to register data to read value supplied to argument of system call
                        // First six syscall arguments are in rdi, rsi, rdx, rcx, r8d, r9d in x86_64 systems
                        // and x0, x1, x2, x3, x4, x5 in Aarch64 systems
                        let mut regs = loop {
                            match ptrace::getregs(target) {
                                Ok(r) => break r,
                                Err(e) => {
                                    if e == Errno::EBUSY || e == Errno::EFAULT || e == Errno::ESRCH
                                    {
                                        continue;
                                    }
                                    debug!("Error while retrieving syscall info: {:?}", e);
                                    return Ok(());
                                }
                            }
                        };
                        // syscall name will be stored to rax on x86_64 system and x8 on Aarch64
                        let syscall = ScmpSyscall::from(syscall_name!(regs) as i32);
                        let syscall_name = syscall
                            .get_name()
                            .expect("unexpected error while retrieving syscall name");
                        debug!("seccomp trap ({})", syscall_name);

                        match syscall_name.as_str() {
                            "fork" | "vfork" | "clone" | "clone3" => {
                                let my_pid = Pid::from_raw(getpid() as i32);
                                let target_exec_path = panic_if_err!(utils::get_executable(target));
                                let jail_path =
                                    panic_if_err!(env::current_exe()).display().to_string();
                                let my_exec_path = panic_if_err!(utils::get_executable(my_pid));
                                if my_exec_path == target_exec_path || my_exec_path == jail_path {
                                    allow = true;
                                } else {
                                    let max_forks = self.policy_inst.get_fork_allowance();
                                    debug!("max_forks: {}", max_forks);
                                    allow = max_forks == -1 || self.fork_count < max_forks;
                                    self.fork_count += 1;
                                }
                                let max_count = self.policy_inst.get_max_child_procs();
                                allow = allow && (max_count == -1 || self.child_count < max_count);
                                debug!("fork owner: {}", target_exec_path);
                            }
                            "tgkill" => {
                                let target_tgid = syscall_arg1!(regs);
                                let target_tid = syscall_arg2!(regs);
                                let signum: Signal =
                                    unsafe { std::mem::transmute(syscall_arg3!(regs) as i32) };
                                allow = match signum {
                                    Signal::SIGKILL | Signal::SIGINT | Signal::SIGTERM => {
                                        target_tgid != getpid() as u64
                                            && target_tid != getpid() as u64
                                            && target_tid != child.as_raw() as u64
                                            && !(target_tid == 0 && child == target)
                                            && target_tid != 1
                                    }
                                    _ => true,
                                };
                            }
                            "kill" | "killpg" | "tkill" => {
                                let target_pid = syscall_arg1!(regs);
                                let signum: Signal =
                                    unsafe { std::mem::transmute(syscall_arg2!(regs) as i32) };
                                allow = match signum {
                                    Signal::SIGKILL | Signal::SIGINT | Signal::SIGTERM => {
                                        target_pid != getpid() as u64
                                            && target_pid != child.as_raw() as u64
                                            && !(target_pid == 0 && child == target)
                                            && target_pid != 1
                                    }
                                    _ => true,
                                };
                            }
                            "execve" | "execveat" => {
                                let my_pid = Pid::from_raw(getpid() as i32);
                                let target_exec_path = panic_if_err!(utils::get_executable(target));
                                let jail_path =
                                    panic_if_err!(env::current_exe()).display().to_string();
                                let my_exec_path = panic_if_err!(utils::get_executable(my_pid));
                                allow = match target_exec_path {
                                    _ if target_exec_path == my_exec_path => true,
                                    _ if target_exec_path == jail_path => true,
                                    _ if self.policy_inst.check_path_op(
                                        &target_exec_path,
                                        PathOps::OpExec,
                                        0,
                                    ) =>
                                    {
                                        true
                                    }
                                    _ => {
                                        let max_exec = self.policy_inst.get_exec_allowance();
                                        self.exec_count += 1;
                                        max_exec == -1 || (self.exec_count - 1) < max_exec
                                    }
                                };
                                extra_info = format!("execve from {}", target_exec_path);
                            }
                            "open" => {
                                let path_str = panic_if_err!(utils::read_string(
                                    target,
                                    syscall_arg1!(regs) as usize
                                ));
                                let path = panic_if_err!(utils::get_abs_path_as(&path_str, target));
                                allow = self.policy_inst.check_path_op(
                                    &path.display().to_string(),
                                    PathOps::OpOpen,
                                    syscall_arg3!(regs) as i32,
                                );
                                extra_info = path.display().to_string();
                            }
                            "access" => {
                                let path_str = panic_if_err!(utils::read_string(
                                    target,
                                    syscall_arg1!(regs) as usize
                                ));
                                let path = panic_if_err!(utils::get_abs_path_as(&path_str, target));
                                allow = self.policy_inst.check_path_op(
                                    &path.display().to_string(),
                                    PathOps::OpAccess,
                                    syscall_arg2!(regs) as i32,
                                );
                                extra_info = path.display().to_string();
                            }
                            "fchmodat" => {
                                let path_str = panic_if_err!(utils::read_string(
                                    target,
                                    syscall_arg2!(regs) as usize
                                ));
                                let path = panic_if_err!(utils::get_abs_path_as(&path_str, target));
                                allow = self.policy_inst.check_path_op(
                                    &path.display().to_string(),
                                    PathOps::OpChmod,
                                    syscall_arg3!(regs) as i32,
                                );
                                extra_info = path.display().to_string();
                            }
                            "chmod" => {
                                let path_str = panic_if_err!(utils::read_string(
                                    target,
                                    syscall_arg1!(regs) as usize
                                ));
                                let path = panic_if_err!(utils::get_abs_path_as(&path_str, target));
                                allow = self.policy_inst.check_path_op(
                                    &path.display().to_string(),
                                    PathOps::OpChmod,
                                    syscall_arg2!(regs) as i32,
                                );
                                extra_info = path.display().to_string();
                            }
                            _ => {
                                allow = true;
                            }
                        }

                        // check if any of loaded plugins require additional jobs on syscall to be executed
                        match self.pre_execution_hooks.get(&syscall_name) {
                            Some(hooks) => {
                                for hook in hooks {
                                    let plugin = self.plugins.get(hook).unwrap();
                                    match plugin.pre_execution_hook(&syscall_name, target, &regs) {
                                        1 => {}
                                        0 if allow => allow = false,
                                        err => {
                                            let errno: Errno = unsafe { std::mem::transmute(err) };
                                            warn!("Error while executing hook: {}", errno);
                                        }
                                    }
                                }
                            }
                            None => {}
                        }

                        // program decided syscall not to be executed
                        if !allow {
                            if extra_info.len() > 0 {
                                warn!("blocked syscall {} ({})", syscall_name, extra_info);
                            } else {
                                warn!("blocked syscall {}", syscall_name);
                            }
                            if !self.cli.watch {
                                // THIS IS NOT A DRILL
                                regs.orig_rax = u64::MAX; // -1

                                // Though we can't halt the actual execution of syscall,
                                // it's possible to alter return value of syscall to -1 (EPERM)
                                // so that caller can think kernel refused to execute syscall
                                regs.rax = u64::MAX - Errno::EPERM as u64 + 1;
                                match ptrace::setregs(target, regs) {
                                    Ok(_) => {}
                                    Err(e) => {
                                        debug!("Error while executing setregs(): {:?}", e);
                                    }
                                }
                            }
                        } else {
                            // calling ptrace(PTRACE_SYSCALL) only if previous steps decide to allow executing syscall

                            // check if any of loaded plugins require additional jobs on syscall after it's executed
                            match self.post_execution_hooks.get(&syscall_name) {
                                Some(hooks) => {
                                    // Continue executing syscall
                                    ptrace::syscall(target, None).unwrap();
                                    // Wait for syscall to be executed
                                    waitpid(target, None).unwrap();
                                    for hook in hooks {
                                        let plugin = self.plugins.get(hook).unwrap();
                                        match plugin.post_execution_hook(
                                            &syscall_name,
                                            target,
                                            &regs,
                                        ) {
                                            0 => {}
                                            err => {
                                                let errno: Errno =
                                                    unsafe { std::mem::transmute(err) };
                                                warn!("Error while executing hook: {}", errno);
                                            }
                                        }
                                    }
                                }
                                None => {}
                            }

                            if extra_info.len() > 0 {
                                debug!("allowed syscall {} ({})", syscall_name, extra_info);
                            } else {
                                debug!("allowed syscall {}", syscall_name);
                            }
                        }
                    }
                    ptrace::Event::PTRACE_EVENT_CLONE
                    | ptrace::Event::PTRACE_EVENT_FORK
                    | ptrace::Event::PTRACE_EVENT_VFORK => {
                        // ptrace will be automatically attached to grandchildren,
                        // because we told to do so when executing PTRACE_SEIZE
                        self.child_count += 1;
                        if self.max_child_count < self.child_count {
                            self.max_child_count = self.child_count;
                        }
                        debug!("child_count is now {}", self.child_count);
                    }
                    ptrace::Event::PTRACE_EVENT_STOP => {}
                    _ => {
                        debug!("Unknown trap cause: {:?}", evt_type);
                    }
                }
            }
            _ => {
                if !child_stopped {
                    signal_to_child = Some(signal);
                    debug!("Injecting unhandled signal: {:?}", signal);
                }
            }
        }
        let mut target_pid = target.as_raw() as u32;
        let target_pid_ptr = &mut target_pid;
        if child_stopped && signal != Signal::SIGTRAP {
            debug!("ptrace-listen");
            let errno_raw = unsafe {
                libc::ptrace(
                    libc::PTRACE_LISTEN,
                    target_pid_ptr as *mut c_uint,
                    std::ptr::null() as *const c_void,
                    std::ptr::null() as *const c_void,
                )
            };
            if errno_raw != 0 {
                error!("errno_raw: {}", errno_raw);
                let errno: Errno = unsafe { std::mem::transmute((errno_raw * -1) as i32) };
                Err(errno)
            } else {
                Ok(())
            }
        } else {
            debug!("ptrace-cont");
            ptrace::cont(target, signal_to_child)
        }
    }

    /// Load seccomp profile and start requested command
    fn run_child(&mut self) {
        debug!("Waiting for debugger to attach");
        unsafe { libc::kill(getpid() as i32, libc::SIGSTOP) };
        debug!("Attached debugger");
        if !self.cli.noop {
            // disallow all calls which aren't described in policy
            let mut filter = panic_if_err!(ScmpFilterContext::new_filter(ScmpAction::Errno(
                libc::EPERM
            )));

            #[cfg(target_arch = "x86_64")]
            panic_if_err!(filter.add_arch(ScmpArch::X8664));

            let mut plugin_hooked_syscalls: HashSet<String> = HashSet::new();
            for (syscall_name, _) in &self.pre_execution_hooks {
                plugin_hooked_syscalls.insert(syscall_name.to_string());
            }
            for (syscall_name, _) in &self.post_execution_hooks {
                plugin_hooked_syscalls.insert(syscall_name.to_string());
            }

            for syscall in self.policy_inst.get_allowed_syscalls() {
                // we won't allow calls which are hooked by plugins
                if plugin_hooked_syscalls.contains(&syscall) {
                    debug!(
                        "Skipping allowing syscall {} (this will be traced by plugin)",
                        syscall
                    );
                    continue;
                }
                match ScmpSyscall::from_name(&syscall) {
                    Ok(syscall_id) => panic_if_err!(filter.add_rule(ScmpAction::Allow, syscall_id)),
                    Err(e) => {
                        warn!("error while allowing syscall {}: {}", syscall, e);
                    }
                }
            }
            for syscall in self.policy_inst.get_traced_syscalls() {
                match ScmpSyscall::from_name(&syscall) {
                    Ok(syscall_id) => {
                        panic_if_err!(filter.add_rule(ScmpAction::Trace(1), syscall_id))
                    }
                    Err(e) => {
                        warn!("error while tracing syscall {}: {}", syscall, e);
                    }
                }
            }
            // we need to track of kill() variants
            for syscall in ["kill", "killpg", "tkill", "tgkill"] {
                match ScmpSyscall::from_name(&syscall) {
                    Ok(syscall_id) => {
                        panic_if_err!(filter.add_rule(ScmpAction::Trace(2), syscall_id))
                    }
                    Err(e) => {
                        warn!("error while tracing syscall {}: {}", syscall, e);
                    }
                }
            }

            // trace syscalls hooked by external plugin
            for syscall in plugin_hooked_syscalls {
                match ScmpSyscall::from_name(&syscall) {
                    Ok(syscall_id) => {
                        panic_if_err!(filter.add_rule(ScmpAction::Trace(3), syscall_id))
                    }
                    Err(e) => {
                        warn!("error while tracing syscall {}: {}", syscall, e);
                    }
                }
            }
            panic_if_err!(filter.set_ctl_nnp(true));
            panic_if_err!(filter.load());
        }

        let bin_path = PathBuf::from(&self.cli.args[0]);
        if !bin_path.exists() {
            panic!("{} not found", self.cli.args[0]);
        }

        let error = Command::new(&bin_path)
            .args(self.cli.args.get_mut(1..).unwrap())
            .exec();

        // we should not reach here
        panic!("{:?}", error);
    }
}
