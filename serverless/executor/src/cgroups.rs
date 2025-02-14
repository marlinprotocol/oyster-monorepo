use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};

use anyhow::{anyhow, Context, Result};

// Struct to keep track of the free 'cgroups' available to execute code and their 'oom_kill' count
#[derive(Debug)]
pub struct Cgroups {
    free: Vec<String>,
    oom_kill_count: HashMap<String, u64>,
    oom_kill_line_idx: usize,
}

impl Cgroups {
    pub fn new() -> Result<Cgroups> {
        let free = get_cgroups()?;
        if free.is_empty() {
            return Err(anyhow!("No cgroups found, make sure you have generated cgroups on your system using the instructions in the readme"));
        }

        let oom_kill_line_idx = find_oom_kill_index(free.first().unwrap())?;
        let mut oom_kill_count = HashMap::new();
        for cgroup in free.iter() {
            oom_kill_count.insert(
                cgroup.clone(),
                get_oom_kill_count(&cgroup, oom_kill_line_idx)?,
            );
        }

        Ok(Cgroups {
            free: free,
            oom_kill_count: oom_kill_count,
            oom_kill_line_idx: oom_kill_line_idx,
        })
    }

    pub fn get_free_capacity(&self) -> usize {
        return self.oom_kill_count.len();
    }

    // Reserve a 'cgroup' and remove it from the free list
    pub fn reserve(&mut self) -> Result<String> {
        if self.free.len() == 0 {
            return Err(anyhow!(""));
        }

        Ok(self.free.swap_remove(0))
    }

    // Release a 'cgroup' and add it back to the free list
    pub fn release(&mut self, cgroup: String) {
        self.free.push(cgroup);
    }

    // Check if an 'oom_kill' termination has happened in the specified cgroup
    pub fn is_oom_killed(&mut self, cgroup: String) -> bool {
        if let Ok(count) = get_oom_kill_count(&cgroup, self.oom_kill_line_idx) {
            let stored_count = self.oom_kill_count.get(&cgroup).unwrap().to_owned();
            if count == (stored_count + 1) {
                self.oom_kill_count.insert(cgroup, count);
                return true;
            }
        }

        false
    }

    // Execute the user code using workerd config in the given 'cgroup' which'll provide memory and cpu for the purpose
    #[cfg(not(test))]
    pub fn execute(
        cgroup: &str,
        args: impl IntoIterator<Item = impl AsRef<OsStr>>,
    ) -> Result<Child> {
        let child = Command::new("cgexec")
            .arg("-g")
            .arg("memory,cpu:".to_string() + cgroup)
            .args(args)
            .stderr(Stdio::piped())
            .spawn()?;

        Ok(child)
    }

    #[cfg(test)]
    pub fn execute(
        cgroup: &str,
        args: impl IntoIterator<Item = impl AsRef<OsStr>>,
    ) -> Result<Child> {
        let child = Command::new("sudo")
            .arg("cgexec")
            .arg("-g")
            .arg("memory,cpu:".to_string() + cgroup)
            .args(args)
            .stderr(Stdio::piped())
            .spawn()?;

        Ok(child)
    }
}

// Retrieve the names of the 'cgroups' generated inside the enclave to host user code for execution by workerd runtime
fn get_cgroups() -> Result<Vec<String>> {
    Ok(fs::read_dir("/sys/fs/cgroup")
        .context("Failed to read the directory /sys/fs/cgroup")?
        .filter_map(|dir| {
            dir.ok().and_then(|dir| {
                dir.path().file_name().and_then(|name| {
                    name.to_str().and_then(|x| {
                        if x.starts_with("workerd_") {
                            Some(x.to_owned())
                        } else {
                            None
                        }
                    })
                })
            })
        })
        .collect())
}

// Function to find the index of "oom_kill " in the memory.events file
fn find_oom_kill_index(cgroup: &str) -> Result<usize> {
    let memory_events_path = "/sys/fs/cgroup/".to_owned() + cgroup + "/memory.events";

    fs::read_to_string(memory_events_path)
        .context("Failed to read memory.events file")?
        .lines()
        .enumerate()
        .find(|(_, line)| line.starts_with("oom_kill "))
        .map(|(index, _)| index)
        .context("Failed to find 'oom_kill' entry in memory.events file")
}

fn get_oom_kill_count(cgroup: &str, index: usize) -> Result<u64> {
    let memory_events_path = "/sys/fs/cgroup/".to_owned() + cgroup + "/memory.events";
    let file = File::open(memory_events_path).context("Failed to open memory.events file")?;
    let reader = BufReader::new(file);

    reader
        .lines()
        .nth(index)
        .context("Failed to read the specified line")??
        .split_whitespace()
        .nth(1)
        .context("Failed to extract 'oom_kill' count")?
        .parse::<u64>()
        .context("Failed to parse oom_kill count as u64")
}
