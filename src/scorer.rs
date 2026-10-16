use crate::rules::{Category, Finding, Severity};
use serde::{Deserialize, Serialize};

/// Report summarizing scoring and finding distribution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScoreReport {
    /// Security-only score (0-100)
    pub security_score: u32,
    /// Cost & efficiency score (0-100)
    pub cost_score: u32,
    /// Overall composite score (0-100)
    pub total_score: u32,
    /// Letter grade: A+, A, B, C, D, or F
    pub grade: String,
    /// Total number of findings
    pub total_findings: usize,
    /// Findings with Critical severity
    pub critical_count: usize,
    /// Findings with High severity
    pub high_count: usize,
    /// Findings with Medium severity
    pub medium_count: usize,
    /// Findings with Low severity
    pub low_count: usize,
}

pub struct Scorer;

impl Scorer {
    /// Computes the score report from a list of findings.
    pub fn calculate(findings: &[Finding]) -> ScoreReport {
        let mut sec_deduction: u32 = 0;
        let mut cost_deduction: u32 = 0;

        let mut critical_count = 0;
        let mut high_count = 0;
        let mut medium_count = 0;
        let mut low_count = 0;

        for f in findings {
            let deduction = f.severity.deduction();
            match f.category {
                Category::Security => {
                    sec_deduction = sec_deduction.saturating_add(deduction);
                }
                Category::CostEfficiency => {
                    cost_deduction = cost_deduction.saturating_add(deduction);
                }
            }

            match f.severity {
                Severity::Critical => critical_count += 1,
                Severity::High => high_count += 1,
                Severity::Medium => medium_count += 1,
                Severity::Low => low_count += 1,
            }
        }

        let security_score = 100u32.saturating_sub(sec_deduction);
        let cost_score = 100u32.saturating_sub(cost_deduction);

        // Weighted total: 60% Security, 40% Cost efficiency
        let total_score =
            ((security_score as f32 * 0.6) + (cost_score as f32 * 0.4)).round() as u32;

        let grade = match total_score {
            95..=100 => "A+",
            90..=94 => "A",
            80..=89 => "B",
            70..=79 => "C",
            60..=69 => "D",
            _ => "F",
        }
        .to_string();

        ScoreReport {
            security_score,
            cost_score,
            total_score,
            grade,
            total_findings: findings.len(),
            critical_count,
            high_count,
            medium_count,
            low_count,
        }
    }
}
