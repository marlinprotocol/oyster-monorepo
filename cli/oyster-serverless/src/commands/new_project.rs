use anyhow::{Context, Result};
use clap::Args;
use inquire::{Select, Text};
use reqwest;
use std::fs;
use std::io::Write;
use tracing::info;

#[derive(Args)]
pub struct NewArgs {
    /// Name of the project to create
    #[arg(short, long, required = true)]
    name: String,
}

#[derive(Clone)]
enum Template {
    HelloWorld,
    EthPrice,
}

impl std::fmt::Display for Template {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Template::HelloWorld => write!(f, "Hello World"),
            Template::EthPrice => write!(f, "ETH Price"),
        }
    }
}

#[derive(Clone)]
enum TemplateSource {
    Predefined,
    GithubUrl,
}

impl std::fmt::Display for TemplateSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TemplateSource::Predefined => write!(f, "Select from predefined templates"),
            TemplateSource::GithubUrl => write!(f, "Provide GitHub template URL"),
        }
    }
}

async fn download_template(template_url: &str, project_path: &std::path::Path) -> Result<()> {
    let response = reqwest::get(template_url)
        .await
        .context("Failed to download template")?
        .text()
        .await
        .context("Failed to read template content")?;

    let worker_path = project_path.join("worker.js");
    let mut file = fs::File::create(&worker_path).context("Failed to create worker.js")?;

    file.write_all(response.as_bytes())
        .context("Failed to write template content")?;

    Ok(())
}

pub async fn run_new(args: NewArgs) -> Result<()> {
    let project_path = std::env::current_dir()?.join(&args.name);
    fs::create_dir_all(&project_path)?;

    let sources = vec![TemplateSource::Predefined, TemplateSource::GithubUrl];

    let source = Select::new("Choose template source:", sources)
        .prompt()
        .context("Failed to select template source")?;

    let template_url = match source {
        TemplateSource::Predefined => {
            let templates = vec![Template::HelloWorld, Template::EthPrice];
            let template = Select::new("Select a starter template:", templates)
                .prompt()
                .context("Failed to select template")?;

            let base_url = "https://raw.githubusercontent.com/marlinprotocol/oyster-serverless-templates/master";
            match template {
                Template::HelloWorld => format!("{}/hello-world/worker.js", base_url),
                Template::EthPrice => format!("{}/eth-price/worker.js", base_url),
            }
        }
        TemplateSource::GithubUrl => Text::new("Enter GitHub raw URL for the template:")
            .prompt()
            .context("Failed to get template URL")?,
    };

    download_template(&template_url, &project_path).await?;
    info!("Created new project at {}", project_path.display());
    info!(
        "All subsequent steps should be performed inside the newly created {} directory.",
        &args.name
    );
    Ok(())
}
