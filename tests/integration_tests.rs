use dockerfile_sec_linter::config::Config;
use dockerfile_sec_linter::engine::LinterEngine;
use dockerfile_sec_linter::reporter::Reporter;
use dockerfile_sec_linter::rules::Severity;
use std::path::PathBuf;

#[test]
fn test_e2e_vulnerable_dockerfile_cli_output() {
    let engine = LinterEngine::new();
    let config = Config::default();
    let result = engine
        .lint_file(PathBuf::from("tests/fixtures/Dockerfile.vulnerable"), &config)
        .expect("Should lint successfully");

    let text_report = Reporter::report(&result, "text");
    assert!(text_report.contains("DOCKERFILE CLOUD SECURITY & COST OPTIMIZER"));
    assert!(text_report.contains("SEC001"));
    assert!(text_report.contains("SEC003"));
    assert!(text_report.contains("COST001"));

    let json_report = Reporter::report(&result, "json");
    assert!(json_report.contains(r#""rule_id": "SEC001""#));
    assert!(json_report.contains(r#""grade": "F""#));
}

#[test]
fn test_e2e_policy_failure_on_severity() {
    let engine = LinterEngine::new();
    let mut config = Config::default();
    config.fail_on = Some(Severity::High);

    let result = engine
        .lint_file(PathBuf::from("tests/fixtures/Dockerfile.vulnerable"), &config)
        .expect("Should lint successfully");

    assert!(result.has_failure);
    assert!(result.failure_reason.is_some());
}
