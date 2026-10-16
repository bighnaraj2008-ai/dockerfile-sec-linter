use clap::Parser;
use colored::*;
use dockerfile_sec_linter::cli::{CheckArgs, Cli, ColorChoice, Commands};
use dockerfile_sec_linter::config::Config;
use dockerfile_sec_linter::engine::LinterEngine;
use dockerfile_sec_linter::reporter::Reporter;
use dockerfile_sec_linter::rules::all_rules;
use std::path::Path;
use std::process;

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Rules) => {
            print_rules_catalog();
            process::exit(0);
        }
        Some(Commands::Init { output, force }) => {
            handle_init(&output, force);
            process::exit(0);
        }
        Some(Commands::Check(args)) => {
            run_check(args);
        }
        None => {
            run_check(cli.check_args);
        }
    }
}

fn configure_color(choice: ColorChoice) {
    match choice {
        ColorChoice::Always => colored::control::set_override(true),
        ColorChoice::Never => colored::control::set_override(false),
        ColorChoice::Auto => {}
    }
}

fn run_check(args: CheckArgs) {
    configure_color(args.color);

    // 1. Resolve configuration
    let mut config = if let Some(ref config_path) = args.config {
        match Config::load_from_file(config_path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("{} {}", "Configuration Error:".bright_red().bold(), e);
                process::exit(2);
            }
        }
    } else {
        Config::discover()
    };

    // 2. CLI flag overrides
    for rule in args.ignore {
        config.ignore_rules.push(rule);
    }
    if let Some(fail_on) = args.fail_on {
        config.fail_on = Some(fail_on.into());
    }
    if let Some(min_score) = args.min_score {
        config.min_score = Some(min_score);
    }

    // 3. Verify file existence
    if !args.file.exists() {
        eprintln!(
            "{} Dockerfile not found at '{}'",
            "Error:".bright_red().bold(),
            args.file.display()
        );
        process::exit(2);
    }

    // 4. Execute analysis
    let engine = LinterEngine::new();
    let result = match engine.lint_file(&args.file, &config) {
        Ok(res) => res,
        Err(e) => {
            eprintln!("{} {}", "Analysis Error:".bright_red().bold(), e);
            process::exit(2);
        }
    };

    // 5. Render report
    let formatted = Reporter::report(&result, &args.format);
    println!("{}", formatted);

    // 6. Exit code enforcement
    if result.has_failure {
        process::exit(1);
    } else {
        process::exit(0);
    }
}

fn print_rules_catalog() {
    println!(
        "\n{}\n",
        "Registered Cloud Security & Cost Optimization Rules:"
            .bold()
            .bright_cyan()
    );

    let rules = all_rules();
    for rule in rules {
        let meta = rule.metadata();
        let sev_badge = match meta.severity {
            dockerfile_sec_linter::rules::Severity::Critical => {
                "[CRITICAL]".on_bright_red().black().bold()
            }
            dockerfile_sec_linter::rules::Severity::High => "[HIGH]".bright_red().bold(),
            dockerfile_sec_linter::rules::Severity::Medium => "[MEDIUM]".bright_yellow().bold(),
            dockerfile_sec_linter::rules::Severity::Low => "[LOW]".bright_blue().bold(),
        };

        println!(
            "  {} {:<8} - {} [{}]",
            sev_badge,
            meta.id.bold().white(),
            meta.name.bold(),
            meta.category.to_string().cyan()
        );
        println!("     {}", meta.description.dimmed());
        println!("     Fix: {}\n", meta.remediation.green());
    }
}

fn handle_init(output: &Path, force: bool) {
    if output.exists() && !force {
        eprintln!(
            "{} File '{}' already exists. Use --force to overwrite.",
            "Error:".bright_red().bold(),
            output.display()
        );
        process::exit(1);
    }

    let template = include_str!("../.dockerlint.example.toml");
    if let Err(e) = std::fs::write(output, template) {
        eprintln!(
            "{} Failed to write configuration to '{}': {}",
            "Error:".bright_red().bold(),
            output.display(),
            e
        );
        process::exit(1);
    }

    println!(
        "{} Created configuration template at '{}'",
        "Success:".bright_green().bold(),
        output.display()
    );
}
