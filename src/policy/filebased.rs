use crate::policy::traits::{SandboxPolicy, PathOps, PolicyConf, PolicyError};

use std::{fs::File, collections::{HashMap, HashSet}};

pub struct FileBasedPolicy {
    pub file_name: String,
    conf: PolicyConf,
}

impl FileBasedPolicy {
    pub fn generate_from_yaml(policy_file: &Option<String>) -> Result<FileBasedPolicy, PolicyError> {
        let default_conf = PolicyConf::default();
        let mut filename = "".to_string();
        let mut policy_conf = match policy_file {
            Some(t) if t.len() > 0 => {
                filename = t.to_owned();
                let file = File::open(t)?;
                let mut read_conf: PolicyConf = serde_yaml::from_reader(file)?;
                read_conf.traced_syscalls = default_conf.traced_syscalls;
                read_conf
            },
            _ => {
                PolicyConf::default()
            }
        };

        if policy_conf.diff_to_default {
            let mut merged_extra_envs: HashMap<String, String> = HashMap::new();
            let mut merged_preserved_env_keys: HashSet<String> = HashSet::new();
            let mut merged_allowed_syscalls: HashSet<String> = HashSet::new();

            for env in default_conf.extra_envs {
                let split: Vec<_> = env.split('=').collect();
                merged_extra_envs.insert(split[0].to_owned(), split[1].to_owned());
            }
            for env in policy_conf.extra_envs {
                let split: Vec<_> = env.split('=').collect();
                merged_extra_envs.insert(split[0].to_owned(), split[1].to_owned());
            }
            policy_conf.extra_envs = Vec::new();
            for (key, value) in merged_extra_envs.into_iter() {
                policy_conf.extra_envs.push(format!("{}={}", key, value));
            }

            for key in default_conf.preserved_env_keys {
                merged_preserved_env_keys.insert(key);
            }
            for key in policy_conf.preserved_env_keys {
                merged_preserved_env_keys.insert(key);
            }
            policy_conf.preserved_env_keys = Vec::new();
            for key in merged_preserved_env_keys {
                policy_conf.preserved_env_keys.push(key);
            }

            for key in default_conf.allowed_syscalls {
                merged_allowed_syscalls.insert(key);
            }
            for key in policy_conf.allowed_syscalls {
                merged_allowed_syscalls.insert(key);
            }
            policy_conf.allowed_syscalls = Vec::new();
            for key in merged_allowed_syscalls {
                policy_conf.allowed_syscalls.push(key.to_string());
            }
        }

        Ok(
            FileBasedPolicy {
                file_name: filename.to_string(),
                conf: policy_conf,
            }
        )
    }
}

impl SandboxPolicy for FileBasedPolicy {
    fn check_path_op(&self, path: &str, op: PathOps, mode: i32) -> bool {
        let matchers = self.conf.whitelist_paths.get(&op).expect(&format!("Op {:?} does not exist", op));
        for matcher in matchers {
            let pattern = glob::Pattern::new(matcher).unwrap();
            if pattern.matches(path) {
                return true;
            }
        }
        return false;
    }

    fn get_exec_allowance(&self) -> i32 {
        let ret = self.conf.exec_allowance;
        return ret;
    }

    fn get_fork_allowance(&self) -> i32 {
        let ret = self.conf.fork_allowance;
        return ret;
    }

    fn get_max_child_procs(&self) -> i32 {
        let ret = self.conf.max_child_procs;
        return ret;
    }

    fn get_extra_envs(&self) -> Vec<String> {
        return self.conf.extra_envs.to_vec();
    }

    fn get_preserved_env_keys(&self) -> Vec<String> {
        return self.conf.preserved_env_keys.to_vec();
    }

    fn get_traced_syscalls(&self) -> Vec<String> {
        return self.conf.traced_syscalls.to_vec();
    }

    fn get_allowed_syscalls(&self) -> Vec<String> {
        return self.conf.allowed_syscalls.to_vec();
    }
}
