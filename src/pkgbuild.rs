use regex::Regex;
use std::collections::HashMap;
use crate::errors::{AurCheckError, Result};

#[derive(Debug, Clone)]
pub struct PkgBuild {
    pub content: String,
    pub variables: HashMap<String, Vec<String>>,
    pub functions: HashMap<String, String>,
}

impl PkgBuild {
    pub fn parse(content: &str) -> Result<Self> {
        let mut variables = HashMap::new();
        let mut functions = HashMap::new();

        let variable_regex = Regex::new(r"^([a-zA-Z_][a-zA-Z0-9_]*)=(.+)$")
            .map_err(|e| AurCheckError::ParseError(e.to_string()))?;
        
        let array_regex = Regex::new(r"^([a-zA-Z_][a-zA-Z0-9_]*)=\((.*)\)$")
            .map_err(|e| AurCheckError::ParseError(e.to_string()))?;

        let function_regex = Regex::new(r"^([a-zA-Z_][a-zA-Z0-9_]*)\(\)\s*\{")
            .map_err(|e| AurCheckError::ParseError(e.to_string()))?;

        let lines: Vec<&str> = content.lines().collect();
        let mut i = 0;

        while i < lines.len() {
            let line = lines[i].trim();
            
            if line.is_empty() || line.starts_with('#') {
                i += 1;
                continue;
            }

            if let Some(caps) = array_regex.captures(line) {
                let var_name = caps.get(1).ok_or_else(|| AurCheckError::ParseError("Invalid array variable name".to_string()))?.as_str();
                let array_content = caps.get(2).ok_or_else(|| AurCheckError::ParseError("Invalid array content".to_string()))?.as_str();
                let values = Self::parse_array_content(array_content)?;
                variables.insert(var_name.to_string(), values);
            } else if let Some(caps) = variable_regex.captures(line) {
                let var_name = caps.get(1).ok_or_else(|| AurCheckError::ParseError("Invalid variable name".to_string()))?.as_str();
                let var_value = caps.get(2).ok_or_else(|| AurCheckError::ParseError("Invalid variable value".to_string()))?.as_str().trim_matches('"').trim_matches('\'');
                variables.insert(var_name.to_string(), vec![var_value.to_string()]);
            } else if let Some(caps) = function_regex.captures(line) {
                let func_name = caps.get(1).ok_or_else(|| AurCheckError::ParseError("Invalid function name".to_string()))?.as_str();
                let func_body = Self::extract_function_body(&lines, &mut i)?;
                functions.insert(func_name.to_string(), func_body);
                continue;
            }

            i += 1;
        }

        Ok(PkgBuild {
            content: content.to_string(),
            variables,
            functions,
        })
    }

    fn parse_array_content(content: &str) -> Result<Vec<String>> {
        let mut values = Vec::new();
        let mut current_value = String::new();
        let mut in_quotes = false;
        let mut quote_char = ' ';
        let mut escaped = false;
        let mut paren_depth = 0;
        let mut brace_depth = 0;

        for ch in content.chars() {
            if escaped {
                current_value.push(ch);
                escaped = false;
                continue;
            }

            match ch {
                '\\' => {
                    escaped = true;
                    current_value.push(ch);
                }
                '"' | '\'' if !in_quotes => {
                    in_quotes = true;
                    quote_char = ch;
                    current_value.push(ch);
                }
                '"' | '\'' if in_quotes && ch == quote_char => {
                    in_quotes = false;
                    quote_char = ' ';
                    current_value.push(ch);
                }
                '(' if !in_quotes => {
                    paren_depth += 1;
                    current_value.push(ch);
                }
                ')' if !in_quotes => {
                    paren_depth -= 1;
                    current_value.push(ch);
                }
                '{' if !in_quotes => {
                    brace_depth += 1;
                    current_value.push(ch);
                }
                '}' if !in_quotes => {
                    brace_depth -= 1;
                    current_value.push(ch);
                }
                ' ' | '\t' | '\n' if !in_quotes && paren_depth == 0 && brace_depth == 0 => {
                    if !current_value.trim().is_empty() {
                        let cleaned = Self::clean_value(&current_value);
                        if !cleaned.is_empty() {
                            values.push(cleaned);
                        }
                        current_value.clear();
                    }
                }
                _ => {
                    current_value.push(ch);
                }
            }
        }

        if !current_value.trim().is_empty() {
            let cleaned = Self::clean_value(&current_value);
            if !cleaned.is_empty() {
                values.push(cleaned);
            }
        }

        Ok(values)
    }

    fn clean_value(value: &str) -> String {
        let trimmed = value.trim();
        
        // Remove outer quotes if they match
        if (trimmed.starts_with('"') && trimmed.ends_with('"')) ||
           (trimmed.starts_with('\'') && trimmed.ends_with('\'')) {
            if trimmed.len() >= 2 {
                return trimmed[1..trimmed.len()-1].to_string();
            }
        }
        
        trimmed.to_string()
    }

    fn extract_function_body(lines: &[&str], index: &mut usize) -> Result<String> {
        let mut body = String::new();
        let mut brace_count = 0;
        let mut started = false;
        let mut in_string = false;
        let mut in_comment = false;
        let mut escape_next = false;
        let mut quote_char = ' ';

        while *index < lines.len() {
            let line = lines[*index];
            
            for ch in line.chars() {
                if escape_next {
                    escape_next = false;
                    continue;
                }

                if ch == '\\' {
                    escape_next = true;
                    continue;
                }

                if !in_string && ch == '#' {
                    in_comment = true;
                }

                if in_comment {
                    continue;
                }

                if !in_string && (ch == '"' || ch == '\'') {
                    in_string = true;
                    quote_char = ch;
                    continue;
                }

                if in_string && ch == quote_char {
                    in_string = false;
                    quote_char = ' ';
                    continue;
                }

                if !in_string {
                    match ch {
                        '{' => {
                            brace_count += 1;
                            started = true;
                        }
                        '}' => {
                            brace_count -= 1;
                            if started && brace_count == 0 {
                                return Ok(body);
                            }
                        }
                        _ => {}
                    }
                }
            }

            if started {
                body.push_str(line);
                body.push('\n');
            }

            in_comment = false;
            *index += 1;
        }

        Ok(body)
    }

    pub fn get_sources(&self) -> Vec<String> {
        let mut sources = Vec::new();
        
        // Standard source array
        if let Some(source_array) = self.variables.get("source") {
            sources.extend(source_array.clone());
        }
        
        // Architecture-specific sources
        for arch in &["x86_64", "i686", "arm", "armv6h", "armv7h", "aarch64"] {
            let arch_source = format!("source_{}", arch);
            if let Some(arch_sources) = self.variables.get(&arch_source) {
                sources.extend(arch_sources.clone());
            }
        }
        
        sources
    }

    pub fn get_checksums(&self) -> Vec<String> {
        let mut checksums = Vec::new();
        
        // Standard checksum types
        for checksum_type in &["md5sums", "sha1sums", "sha224sums", "sha256sums", "sha384sums", "sha512sums", "b2sums"] {
            if let Some(sums) = self.variables.get(*checksum_type) {
                checksums.extend(sums.clone());
            }
        }
        
        // Architecture-specific checksums
        for arch in &["x86_64", "i686", "arm", "armv6h", "armv7h", "aarch64"] {
            for checksum_type in &["md5sums", "sha1sums", "sha256sums", "sha512sums", "b2sums"] {
                let arch_checksum = format!("{}_{}", checksum_type, arch);
                if let Some(sums) = self.variables.get(&arch_checksum) {
                    checksums.extend(sums.clone());
                }
            }
        }
        
        checksums
    }

}