#[derive(Debug)]
pub enum Dependency {
    Docker,
}

impl Dependency {
    pub fn command(&self) -> &'static str {
        match self {
            Dependency::Docker => "docker",
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Dependency::Docker => "Docker",
        }
    }

    pub fn install_url(&self) -> &'static str {
        match self {
            Dependency::Docker => "https://docs.docker.com/engine/install/",
        }
    }
}
