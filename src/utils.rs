use derive_more::From;
use libc::c_void;
use nix::errno::Errno;
use nix::sys::ptrace;
use nix::unistd::Pid;
use std::env;
use std::fs;
use std::io::prelude::*;
use std::path::{Path, PathBuf};

#[derive(From, Debug)]
pub enum ByteOpsError {
    SysError(Errno),
    IOError(std::io::Error),
    StringConversionError(std::string::FromUtf8Error),
}

const PATH_MAX: u32 = 0x1000;

#[macro_export]
macro_rules! vec_of_strings {
    ($($x:expr),*) => (vec![$($x.to_string()),*]);
}

#[macro_export]
macro_rules! panic_if_err {
    ( $x:expr ) => {{
        match $x {
            Ok(i) => i,
            Err(e) => panic!("{:?}", e),
        }
    }};
}

pub fn filter_envs(preserved_env_keys: &Vec<String>) -> Vec<String> {
    let mut enabled_envs = Vec::new();
    let envs = env::vars();
    for (key, value) in envs {
        if preserved_env_keys.contains(&key) {
            enabled_envs.push(format!("{}={}", &key, &value));
        }
    }
    enabled_envs
}

pub fn get_executable(pid: Pid) -> Result<String, ByteOpsError> {
    let deleted_tag = " (deleted)";
    let mut path = fs::read_link(format!("/proc/{}/exe", pid.as_raw()))?
        .display()
        .to_string()
        .trim_end_matches(deleted_tag)
        .trim_end_matches(deleted_tag)
        .to_string();

    if path == "/bin/sh" || path == "/bin/bash" || path == "/bin/dash" {
        let mut file = fs::File::open(format!("/proc/{}/cmdline", pid.as_raw()))?;
        let mut buf = [0; 1024];
        file.read(&mut buf)?;
        let data = String::from_utf8(buf.to_vec())?;
        let cmd: Vec<&str> = data.split('\x00').collect();
        if !cmd[1].starts_with('/') && cmd[1] != "/usr/bin/env" {
            let cwd = fs::read_link(format!("/proc/{}/cwd", pid.as_raw()))?;
            path = cwd.join(cmd[1]).display().to_string();
        } else {
            path = cmd[1].to_string();
        }
    }
    Ok(path)
}

pub fn read_string(pid: Pid, addr_raw: usize) -> Result<String, ByteOpsError> {
    let mut out: Vec<u8> = Vec::new();
    'outer: for i in 0..(PATH_MAX / 8) {
        let data = ptrace::read(pid, (addr_raw + (i * 8) as usize) as *mut c_void)?;
        for j in 0..8 {
            let char = (data >> (j * 8)) as u8;
            if char == '\0' as u8 {
                break 'outer;
            }
            out.push(char);
        }
    }

    Ok(String::from_utf8(out)?)
}

pub fn get_abs_path_as(path_: &str, pid: Pid) -> Result<PathBuf, ByteOpsError> {
    let path = Path::new(path_);
    if path.is_absolute() {
        Ok(clean_path::clean(path))
    } else {
        let pwd_path = format!("/proc/{}/cwd", pid.as_raw());
        let mut pwd = fs::read_link(pwd_path)?;
        let path_ = clean_path::clean(&mut pwd);
        Ok(pwd.join(path_))
    }
}
