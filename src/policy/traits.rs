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
    #[serde(rename(deserialize = "OP_OPEN"))]
    OpOpen = 1,
    #[serde(rename(deserialize = "OP_ACCESS"))]
    OpAccess = 2,
    #[serde(rename(deserialize = "OP_EXEC"))]
    OpExec = 3,
    #[serde(rename(deserialize = "OP_STAT"))]
    OpStat = 4,
    #[serde(rename(deserialize = "OP_CHMOD"))]
    OpChmod = 5,
}

impl Default for PolicyConf {
    fn default() -> Self {
        let arch = "amd64";
        let policy_file = std::fs::read_to_string(format!("./default-policies/default-policy.{arch}.yml")).unwrap();
        let policy_conf: PolicyConf = serde_yaml::from_str(&policy_file).unwrap();
        policy_conf
    }
}