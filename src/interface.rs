use std::any::Any;

use clap::Parser;
use libc::user_regs_struct;
use nix::unistd::Pid;

/// All jail plugins need to implement this interface
/// and a function with signature pub extern "Rust" fn load() -> *mut dyn PluginInterface;
/// which returns `Box`ed struct
pub trait PluginInterface: Any + Send + Sync {
    /// Returns name of plugin itself
    fn get_name(&self) -> &'static str;
    /// Store syscalls hooked by the plugin
    ///
    /// * Arguments
    /// - `hooks`: vector to store definition of hooked syscalls
    fn get_hooked_syscalls(&self, hooks: &mut Vec<SyscallHook>);
    /// Hook to be executed before actual execution of system call
    ///
    /// * Arguments
    /// - `name`: Name of system call
    /// - `pid`: PID of child calling system call
    /// - `regs`: Register info
    /// * Returns
    /// Possible return values are:
    /// - 1: allow syscall to be executed
    /// - 0: deny execution of syscall
    /// - <0: Errno
    fn pre_execution_hook(&self, name: &str, pid: Pid, regs: &user_regs_struct) -> i32;
    /// Hook to be executed after execution of system call
    /// This can't block execution of system call,
    /// but can benefit when hook need to alter result provided by system call
    ///
    /// * Arguments
    /// - `name`: Name of system call
    /// - `pid`: PID of child calling system call
    /// - `regs`: Register info
    /// * Returns
    /// Possible return values are:
    /// - 0: hook executed without error
    /// - <0: Errno
    fn post_execution_hook(&self, name: &str, pid: Pid, regs: &user_regs_struct) -> i32;
    fn process_did_create(&mut self, pid: Pid);
    fn process_did_terminate(&mut self, pid: Pid);
}

#[derive(PartialEq, Hash, Clone, Debug)]
pub struct SyscallHook {
    pub name: String,
    pub hook_type: HookType,
}

#[derive(PartialEq, Hash, Clone, Debug)]
pub enum HookType {
    /// This hook should be ran before executing system call
    PRE,
    /// This hook should be ran after executing system call
    POST,
    /// This hook should be ran both before and after executing system call
    BOTH,
}

/// A dynamic sandbox for Backend.AI kernels
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    pub args: Vec<String>,

    /// Path to policy config file. If set to default, it uses the embedded default policy.
    #[arg(short, long)]
    pub policy: Option<String>,

    /// Set the debug mode. Shows every detail of syscalls.
    #[arg(short, long)]
    pub log_level: Option<String>,

    /// Set the watch mode. Shows syscalls blocked by the policy.
    #[arg(short, long)]
    pub watch: bool,

    /// Set the no-op mode. Jail becomes a completely transparent exec wrapper.
    #[arg(short, long)]
    pub noop: bool,
}
