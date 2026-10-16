use crate::ast::Dockerfile;
use crate::config::Config;
use crate::error::Result;
use crate::parser::DockerfileParser;
use crate::rules::{all_rules, Finding, Rule};
use crate::scorer::{ScoreReport, Scorer};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Aggregate outcome of a linting run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LintResult {
    pub file_path: String,
    pub findings: Vec<Finding>,
    pub score: ScoreReport,
    pub has_failure: bool,
    pub failure_reason: Option<String>,
    pub stages_count: usize,
    pub instructions_count: usize,
}

pub struct LinterEngine {
    rules: Vec<Box<dyn Rule>>,
}

impl Default for LinterEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl LinterEngine {
    /// Creates a new linter engine populated with default built-in rules.
    pub fn new() -> Self {
        Self { rules: all_rules() }
    }

    /// Lints a Dockerfile from an in-memory string.
    pub fn lint_str(&self, content: &str, file_label: &str, config: &Config) -> Result<LintResult> {
        let dockerfile = DockerfileParser::parse_str(content)?;
        self.lint_ast(&dockerfile, file_label, config)
    }

    /// Lints a Dockerfile from disk.
    pub fn lint_file<P: AsRef<Path>>(&self, path: P, config: &Config) -> Result<LintResult> {
        let p = path.as_ref();
        let dockerfile = DockerfileParser::parse_file(p)?;
        self.lint_ast(&dockerfile, &p.display().to_string(), config)
    }

    /// Evaluates the AST against all active rules and calculates the result.
    pub fn lint_ast(
        &self,
        dockerfile: &Dockerfile,
        file_label: &str,
        config: &Config,
    ) -> Result<LintResult> {
        let mut raw_findings = Vec::new();

        for rule in &self.rules {
            let meta = rule.metadata();

            // Skip ignored rules
            if config.is_rule_ignored(meta.id) {
                continue;
            }

            // Skip rules below minimum severity threshold
            if meta.severity < config.min_severity {
                continue;
            }

            let mut findings = rule.check(dockerfile, config);
            raw_findings.append(&mut findings);
        }

        // Sort findings: Critical -> High -> Medium -> Low, then by line number
        raw_findings.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| a.line_number.cmp(&b.line_number))
        });

        let score = Scorer::calculate(&raw_findings);

        // Check for threshold violations
        let mut has_failure = false;
        let mut failure_reason = None;

        if let Some(min_score) = config.min_score {
            if score.total_score < min_score {
                has_failure = true;
                failure_reason = Some(format!(
                    "Score {} is below required minimum threshold of {}",
                    score.total_score, min_score
                ));
            }
        }

        if let Some(fail_severity) = config.fail_on {
            let max_finding_severity = raw_findings.iter().map(|f| f.severity).max();
            if let Some(max_sev) = max_finding_severity {
                if max_sev >= fail_severity {
                    has_failure = true;
                    let msg = format!(
                        "Found violations with severity {} which meets or exceeds '--fail-on {}'",
                        max_sev, fail_severity
                    );
                    failure_reason = match failure_reason {
                        Some(prev) => Some(format!("{}; {}", prev, msg)),
                        None => Some(msg),
                    };
                }
            }
        }

        let instructions_count = dockerfile.all_instructions().len();

        Ok(LintResult {
            file_path: file_label.to_string(),
            findings: raw_findings,
            score,
            has_failure,
            failure_reason,
            stages_count: dockerfile.stages.len(),
            instructions_count,
        })
    }
}
