use dockerfile_sec_linter::rules::{Category, Finding, Severity};
use dockerfile_sec_linter::scorer::Scorer;

#[test]
fn test_perfect_score_zero_findings() {
    let findings: Vec<Finding> = Vec::new();
    let report = Scorer::calculate(&findings);

    assert_eq!(report.total_score, 100);
    assert_eq!(report.security_score, 100);
    assert_eq!(report.cost_score, 100);
    assert_eq!(report.grade, "A+");
    assert_eq!(report.total_findings, 0);
}

#[test]
fn test_deductions_and_grades() {
    let findings = vec![
        Finding {
            rule_id: "SEC003".to_string(),
            rule_name: "Hardcoded secret".to_string(),
            category: Category::Security,
            severity: Severity::Critical,
            line_number: 10,
            message: "Secret found".to_string(),
            remediation: "Remove".to_string(),
            code_snippet: None,
            stage_index: 0,
        },
        Finding {
            rule_id: "COST001".to_string(),
            rule_name: "Bloated image".to_string(),
            category: Category::CostEfficiency,
            severity: Severity::Medium,
            line_number: 1,
            message: "Bloated".to_string(),
            remediation: "Use alpine".to_string(),
            code_snippet: None,
            stage_index: 0,
        },
    ];

    let report = Scorer::calculate(&findings);

    assert_eq!(report.security_score, 75);
    assert_eq!(report.cost_score, 92);
    assert_eq!(report.total_score, 82);
    assert_eq!(report.grade, "B");
    assert_eq!(report.critical_count, 1);
    assert_eq!(report.medium_count, 1);
}
