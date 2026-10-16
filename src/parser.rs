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
impl DockerfileParser {
    fn parse_from(rest: &str, line_number: usize, raw: &str) -> Result<FromInstruction> {
        let tokens = Self::tokenize_whitespace(rest);
        if tokens.is_empty() {
            return Err(LinterError::Parse {
                line: line_number,
                message: "FROM instruction missing base image target".to_string(),
            });
        }

        let mut platform = None;
        let mut image_token_idx = 0;

        for (i, tok) in tokens.iter().enumerate() {
            if let Some(p) = tok.strip_prefix("--platform=") {
                platform = Some(p.to_string());
                image_token_idx = i + 1;
            } else {
                break;
            }
        }

        if image_token_idx >= tokens.len() {
            return Err(LinterError::Parse {
                line: line_number,
                message: "FROM instruction missing base image target after flags".to_string(),
            });
        }

        let full_image = tokens[image_token_idx].clone();
        let mut alias = None;
        for i in (image_token_idx + 1)..tokens.len() {
            if tokens[i].eq_ignore_ascii_case("AS") && i + 1 < tokens.len() {
                alias = Some(tokens[i + 1].clone());
                break;
            }
        }

        let (image_name, tag, digest) = Self::parse_image_components(&full_image);

        Ok(FromInstruction {
            full_image,
            image_name,
            tag,
            digest,
            alias,
            platform,
            line_number,
            raw: raw.to_string(),
        })
    }

    fn parse_image_components(full: &str) -> (String, Option<String>, Option<String>) {
        let mut digest = None;
        let mut remainder = full;

        if let Some(pos) = full.find('@') {
            digest = Some(full[pos + 1..].to_string());
            remainder = &full[..pos];
        }

        let mut tag = None;
        let mut repo = remainder.to_string();

        if let Some(last_colon) = remainder.rfind(':') {
            let last_slash = remainder.rfind('/');
            let is_tag_colon = match last_slash {
                Some(slash_pos) => last_colon > slash_pos,
                None => true,
            };

            if is_tag_colon {
                tag = Some(remainder[last_colon + 1..].to_string());
                repo = remainder[..last_colon].to_string();
            }
        }

        (repo, tag, digest)
    }
}
