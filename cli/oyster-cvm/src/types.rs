use clap::ValueEnum;

#[derive(Debug, Clone, Default)]
pub enum Platform {
    AMD64,
    #[default]
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
            Platform::AMD64 => "x86_64-linux",
            Platform::ARM64 => "aarch64-linux",
        }
    }

    // TODO: Add default marlin local dev base images
    pub fn base_dev_image(&self) -> &'static str {
        match self {
            Platform::AMD64 => "ayushkyadav/local_dev_image_amd64:latest",
            Platform::ARM64 => "ayushkyadav/local_dev_image_arm64:latest",
        }
    }
}

impl ValueEnum for Platform {
    fn value_variants<'a>() -> &'a [Self] {
        &[Self::AMD64, Self::ARM64]
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        Some(self.as_str().into())
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
            StorageProvider::Pinata => "pinata",
        }
    }
}
