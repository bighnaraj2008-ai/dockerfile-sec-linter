use crate::engine::LintResult;
use crate::rules::{Category, Severity};
use colored::*;

pub struct Reporter;

impl Reporter {
    pub fn report(result: &LintResult, _format: &str) -> String {
        Self::format_text(result)
    }

    pub fn format_text(result: &LintResult) -> String {
        let mut out = String::new();

        out.push_str(&format!(
            "\n{}\n",
            "╔══════════════════════════════════════════════════════════════════════════════╗"
                .bright_cyan()
        ));
        out.push_str(&format!(
            "║  {}  ║\n",
            "DOCKERFILE CLOUD SECURITY & COST OPTIMIZER".bold().bright_white()
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
                format!("FINDINGS ({})", result.findings.len()).bold().yellow()
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

        out
    }
}
