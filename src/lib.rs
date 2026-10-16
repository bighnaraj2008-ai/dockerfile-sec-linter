//! dockerfile-sec-linter
//!
//! A cloud security and cost-optimization Dockerfile static analyzer.

pub mod ast;
pub mod cli;
pub mod config;
pub mod engine;
pub mod error;
pub mod parser;
pub mod reporter;
pub mod rules;
pub mod scorer;

pub use ast::{Dockerfile, Instruction, Stage};
pub use config::Config;
pub use engine::{LintResult, LinterEngine};
pub use error::{LinterError, Result};
pub use parser::DockerfileParser;
pub use reporter::Reporter;
pub use rules::{all_rules, Category, Finding, Rule, Severity};
pub use scorer::{ScoreReport, Scorer};
