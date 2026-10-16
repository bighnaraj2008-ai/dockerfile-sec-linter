use crate::ast::*;
use crate::error::{LinterError, Result};
use std::path::Path;

/// Parser for Dockerfile syntax.
pub struct DockerfileParser;

#[derive(Debug, Clone)]
struct LogicalLine {
    start_line: usize,
    raw_content: String,
    normalized: String,
}

impl DockerfileParser {
    fn split_keyword(line: &str) -> (&str, &str) {
        let trimmed = line.trim();
        if let Some(pos) = trimmed.find(|c: char| c.is_whitespace()) {
            let (kw, rest) = trimmed.split_at(pos);
            (kw.trim(), rest.trim())
        } else {
            (trimmed, "")
        }
    }
}
impl DockerfileParser {
    fn extract_logical_lines(content: &str) -> Vec<LogicalLine> {
        let mut logical_lines = Vec::new();
        let mut current_buf = String::new();
        let mut raw_buf = String::new();
        let mut start_line = 1;
        let mut in_continuation = false;

        for (idx, line) in content.lines().enumerate() {
            let line_num = idx + 1;
            let trimmed = line.trim();

            if !in_continuation {
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                start_line = line_num;
                current_buf.clear();
                raw_buf.clear();
            }

            if !raw_buf.is_empty() {
                raw_buf.push('\n');
            }
            raw_buf.push_str(line);

            if let Some(without_slash) = trimmed.strip_suffix('\\') {
                in_continuation = true;
                if !current_buf.is_empty() {
                    current_buf.push(' ');
                }
                current_buf.push_str(without_slash.trim_end());
            } else {
                in_continuation = false;
                if !current_buf.is_empty() {
                    current_buf.push(' ');
                }
                current_buf.push_str(trimmed);

                logical_lines.push(LogicalLine {
                    start_line,
                    raw_content: raw_buf.clone(),
                    normalized: current_buf.trim().to_string(),
                });

                current_buf.clear();
                raw_buf.clear();
            }
        }

        if !current_buf.is_empty() {
            logical_lines.push(LogicalLine {
                start_line,
                raw_content: raw_buf,
                normalized: current_buf.trim().to_string(),
            });
        }

        logical_lines
    }
}
