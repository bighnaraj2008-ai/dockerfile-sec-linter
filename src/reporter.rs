use crate::engine::LintResult;
use crate::rules::{Category, Severity};
use colored::*;

pub struct Reporter;

impl Reporter {
    /// Renders the linting result according to the requested format ("text" or "json").
    pub fn report(result: &LintResult, format: &str) -> String {
        match format.to_lowercase().as_str() {
            "json" => Self::format_json(result),
            _ => Self::format_text(result),
        }
    }

    /// Formats the result as structured, pretty-printed JSON.
    pub fn format_json(result: &LintResult) -> String {
        serde_json::to_string_pretty(result)
            .unwrap_or_else(|e| format!(r#"{{"error": "Failed to serialize JSON: {}"}}"#, e))
    }

    /// Formats the result as rich ANSI-colored terminal output.
    pub fn format_text(result: &LintResult) -> String {
        let mut out = String::new();

        out.push_str(&format!(
            "\n{}\n",
            "╔══════════════════════════════════════════════════════════════════════════════╗"
                .bright_cyan()
        ));
        out.push_str(&format!(
            "║  {}  ║\n",
            "DOCKERFILE CLOUD SECURITY & COST OPTIMIZER"
                .bold()
                .bright_white()
        ));
        out.push_str(&format!(
            "{}\n",
            "╚══════════════════════════════════════════════════════════════════════════════╝"
                .bright_cyan()
        ));

        out.push_str(&format!(
            "  Target File   : {}\n",
            result.file_path.bold().white()
        ));
        out.push_str(&format!(
            "  Build Stages  : {}\n",
            result.stages_count.to_string().cyan()
        ));
        out.push_str(&format!(
            "  Instructions  : {}\n\n",
            result.instructions_count.to_string().cyan()
        ));

        if result.findings.is_empty() {
            out.push_str(&format!(
                "  {} {}\n\n",
                "✔".bright_green().bold(),
                "Zero security vulnerabilities or cost inefficiencies detected! Perfect score."
                    .bright_green()
                    .bold()
            ));
        } else {
            out.push_str(&format!(
                "─── {} ────────────────────────────────────────────────\n\n",
                format!("FINDINGS ({})", result.findings.len())
                    .bold()
                    .yellow()
            ));

            for (idx, f) in result.findings.iter().enumerate() {
                let badge = match f.severity {
                    Severity::Critical => "[CRITICAL]".on_bright_red().black().bold(),
                    Severity::High => "[HIGH]".bright_red().bold(),
                    Severity::Medium => "[MEDIUM]".bright_yellow().bold(),
                    Severity::Low => "[LOW]".bright_blue().bold(),
                };

                let cat_badge = match f.category {
                    Category::Security => "SECURITY".bright_magenta(),
                    Category::CostEfficiency => "COST-EFFICIENCY".bright_cyan(),
                };

                let rule_title = format!("{}: {}", f.rule_id, f.rule_name);
                out.push_str(&format!(
                    " {:2}. {} {}  [{}] (line {})\n",
                    idx + 1,
                    badge,
                    rule_title.bold().white(),
                    cat_badge,
                    f.line_number.to_string().yellow()
                ));

                out.push_str(&format!(
                    "     {} {}\n",
                    "• Issue:".bright_white(),
                    f.message
                ));

                if let Some(ref snippet) = f.code_snippet {
                    let indented = snippet
                        .lines()
                        .map(|l| format!("       │ {}", l.dimmed()))
                        .collect::<Vec<_>>()
                        .join("\n");
                    out.push_str(&format!("{}\n", indented));
                }

                out.push_str(&format!(
                    "     {} {}\n\n",
                    "↳ Fix  :".bright_green().bold(),
                    f.remediation.green()
                ));
            }
        }

        // Score summary card
        out.push_str(&format!(
            "─── {} ────────────────────────────────────────────────────\n\n",
            "METRICS & SCORECARD".bold().bright_cyan()
        ));

        let grade_color = match result.score.grade.as_str() {
            "A+" | "A" => result.score.grade.bright_green().bold(),
            "B" => result.score.grade.bright_cyan().bold(),
            "C" => result.score.grade.bright_yellow().bold(),
            "D" => result.score.grade.bright_red().bold(),
            _ => result.score.grade.on_red().bright_white().bold(),
        };

        out.push_str(&format!(
            "  Composite Health Score : {} / 100  [Grade: {}]\n",
            Self::color_score(result.score.total_score),
            grade_color
        ));
        out.push_str(&format!(
            "  ├── Cloud Security     : {} / 100\n",
            Self::color_score(result.score.security_score)
        ));
        out.push_str(&format!(
            "  └── Cost & Size        : {} / 100\n\n",
            Self::color_score(result.score.cost_score)
        ));

        out.push_str(&format!(
            "  Findings Breakdown: {} Critical | {} High | {} Medium | {} Low\n\n",
            result.score.critical_count.to_string().bright_red().bold(),
            result.score.high_count.to_string().red(),
            result.score.medium_count.to_string().yellow(),
            result.score.low_count.to_string().blue()
        ));

        if result.has_failure {
            if let Some(ref reason) = result.failure_reason {
                out.push_str(&format!(
                    "  {} {}\n\n",
                    "✖ POLICY FAILURE:".bright_red().bold(),
                    reason.red()
                ));
            }
        }

        out
    }

    fn color_score(score: u32) -> ColoredString {
        let s = score.to_string();
        if score >= 90 {
            s.bright_green().bold()
        } else if score >= 70 {
            s.bright_yellow().bold()
        } else {
            s.bright_red().bold()
        }
    }
}
