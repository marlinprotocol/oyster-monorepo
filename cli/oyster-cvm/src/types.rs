#[derive(Debug, Clone)]
pub enum Platform {
    AMD64,
    ARM64,
}

impl Platform {
    pub fn as_str(&self) -> &'static str {
        match self {
            Platform::AMD64 => "amd64",
            Platform::ARM64 => "arm64",
        }
    }

    pub fn nix_arch(&self) -> &'static str {
        match self {
            Platform::AMD64 => "x86_64-linux.musl",
            Platform::ARM64 => "aarch64-linux.musl",
        }
    }

    pub fn from_str(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "amd64" => Ok(Platform::AMD64),
            "arm64" => Ok(Platform::ARM64),
            _ => Err(format!(
                "Unsupported platform: {}. Only amd64 and arm64 are supported",
                s
            )),
        }
    }
}

#[derive(Debug)]
pub enum Dependency {
    Docker,
    Nix,
}

impl Dependency {
    pub fn command(&self) -> &'static str {
        match self {
            Dependency::Docker => "docker",
            Dependency::Nix => "nix",
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Dependency::Docker => "Docker",
            Dependency::Nix => "Nix",
        }
    }

    pub fn install_url(&self) -> &'static str {
        match self {
            Dependency::Docker => "https://docs.docker.com/engine/install/",
            Dependency::Nix => "https://github.com/DeterminateSystems/nix-installer",
        }
    }
}

#[derive(Debug, Clone)]
pub enum StorageProvider {
    Pinata,
}

impl StorageProvider {
    pub fn as_str(&self) -> &'static str {
        match self {
            StorageProvider::Pinata => "pinata"
        }
    }
}
