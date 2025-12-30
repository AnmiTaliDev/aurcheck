use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SecurityLevel {
    Safe,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityIssue {
    pub level: SecurityLevel,
    pub category: String,
    pub title: String,
    pub description: String,
    pub recommendation: String,
    pub location: Option<String>,
    pub context: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityReport {
    pub package_name: String,
    pub overall_level: SecurityLevel,
    pub issues: Vec<SecurityIssue>,
    pub summary: SecuritySummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecuritySummary {
    pub total_issues: usize,
    pub critical_count: usize,
    pub warning_count: usize,
    pub safe_count: usize,
}

impl SecurityReport {
    pub fn new(package_name: String, issues: Vec<SecurityIssue>) -> Self {
        let critical_count = issues.iter().filter(|i| i.level == SecurityLevel::Critical).count();
        let warning_count = issues.iter().filter(|i| i.level == SecurityLevel::Warning).count();
        let safe_count = issues.iter().filter(|i| i.level == SecurityLevel::Safe).count();

        let overall_level = if critical_count > 0 {
            SecurityLevel::Critical
        } else if warning_count > 0 {
            SecurityLevel::Warning
        } else {
            SecurityLevel::Safe
        };

        let summary = SecuritySummary {
            total_issues: issues.len(),
            critical_count,
            warning_count,
            safe_count,
        };

        Self {
            package_name,
            overall_level,
            issues,
            summary,
        }
    }
}
