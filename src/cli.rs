use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "dockerfile-sec-linter",
    author = "Antigravity Developer",
    version = "0.1.0",
    about = "Cloud security and cost-optimization Dockerfile static analyzer",
    long_about = "A production-grade Dockerfile static analyzer that inspects container definitions \
                  for security vulnerabilities (non-root users, unpinned tags, hardcoded secrets, \
                  insecure ADD, sudo usage) and cloud cost inefficiencies (bloated base images, \
                  uncleaned package caches, redundant layer counts)."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    #[command(flatten)]
    pub check_args: CheckArgs,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Lint a Dockerfile (default command)
    Check(CheckArgs),

    /// List all registered security and cost efficiency rules
    Rules,

    /// Generate a default .dockerlint.toml configuration file
    Init {
        /// Destination path for configuration file
        #[arg(short, long, default_value = ".dockerlint.toml")]
        output: PathBuf,
        /// Force overwrite if file already exists
        #[arg(short, long)]
        force: bool,
    },
}

#[derive(Args, Debug, Clone)]
pub struct CheckArgs {
    /// Path to the target Dockerfile to analyze
    #[arg(default_value = "Dockerfile")]
    pub file: PathBuf,

    /// Output report format
    #[arg(short, long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,

    /// Path to optional .dockerlint.toml configuration file
    #[arg(short, long)]
    pub config: Option<PathBuf>,

    /// Fail with non-zero exit code if findings meet or exceed this severity
    #[arg(long, value_enum)]
    pub fail_on: Option<CliSeverity>,

    /// Minimum acceptable score (0-100); fails if total score is below
    #[arg(long)]
    pub min_score: Option<u32>,

    /// Specific rule IDs to ignore (e.g. --ignore COST003 --ignore SEC004)
    #[arg(short, long, value_delimiter = ',')]
    pub ignore: Vec<String>,

    /// Terminal color formatting
    #[arg(long, default_value = "auto", value_enum)]
    pub color: ColorChoice,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum CliSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl From<CliSeverity> for crate::rules::Severity {
    fn from(s: CliSeverity) -> Self {
        match s {
            CliSeverity::Low => crate::rules::Severity::Low,
            CliSeverity::Medium => crate::rules::Severity::Medium,
            CliSeverity::High => crate::rules::Severity::High,
            CliSeverity::Critical => crate::rules::Severity::Critical,
        }
    }
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ColorChoice {
    Auto,
    Always,
    Never,
}
