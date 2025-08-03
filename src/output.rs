use crate::security::{SecurityReport, SecurityIssue, SecurityLevel};
use colored::*;
use serde_json;
use indicatif::{ProgressBar, ProgressStyle};

#[derive(Debug, Clone)]
pub enum OutputFormat {
    Colored,
    Json,
}

pub struct Reporter {
    format: OutputFormat,
    verbose: bool,
}

impl Reporter {
    pub fn new(format: OutputFormat, verbose: bool) -> Self {
        Self { format, verbose }
    }

    pub fn start_scan(&self, package_name: &str) {
        match self.format {
            OutputFormat::Colored => {
                println!("{} {}", "Scanning package:".bold().blue(), package_name.bold());
                
                if self.verbose {
                    let pb = ProgressBar::new_spinner();
                    pb.set_style(ProgressStyle::default_spinner()
                        .template("{spinner:.blue} {msg}")
                        .unwrap_or_else(|_| ProgressStyle::default_spinner()));
                    pb.set_message("Downloading PKGBUILD...");
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    pb.finish_with_message("✓ PKGBUILD downloaded");
                }
            }
            OutputFormat::Json => {}
        }
    }

    pub fn display_results(&self, report: &SecurityReport) {
        match self.format {
            OutputFormat::Colored => self.display_colored_results(report),
            OutputFormat::Json => self.display_json_results(report),
        }
    }

    fn display_colored_results(&self, report: &SecurityReport) {
        println!();
        
        let level_indicator = match report.overall_level {
            SecurityLevel::Safe => "✓ SAFE".green().bold(),
            SecurityLevel::Warning => "⚠ WARNING".yellow().bold(),
            SecurityLevel::Critical => "✗ CRITICAL".red().bold(),
        };

        println!("{} Package: {}", level_indicator, report.package_name.bold());
        println!();

        if report.issues.is_empty() {
            println!("{}", "No security issues found.".green());
            return;
        }

        println!("{}", "Security Issues Found:".bold().underline());
        println!();

        let mut critical_issues = Vec::new();
        let mut warning_issues = Vec::new();
        let mut safe_issues = Vec::new();

        for issue in &report.issues {
            match issue.level {
                SecurityLevel::Critical => critical_issues.push(issue),
                SecurityLevel::Warning => warning_issues.push(issue),
                SecurityLevel::Safe => safe_issues.push(issue),
            }
        }

        if !critical_issues.is_empty() {
            println!("{}", "Critical Issues:".red().bold());
            for issue in critical_issues {
                self.display_issue(issue);
            }
            println!();
        }

        if !warning_issues.is_empty() {
            println!("{}", "Warnings:".yellow().bold());
            for issue in warning_issues {
                self.display_issue(issue);
            }
            println!();
        }

        if !safe_issues.is_empty() && self.verbose {
            println!("{}", "Info:".green().bold());
            for issue in safe_issues {
                self.display_issue(issue);
            }
            println!();
        }

        self.display_summary(report);
    }

    fn display_issue(&self, issue: &SecurityIssue) {
        let level_icon = match issue.level {
            SecurityLevel::Critical => "✗".red(),
            SecurityLevel::Warning => "⚠".yellow(),
            SecurityLevel::Safe => "ℹ".blue(),
        };

        println!("  {} {}", level_icon, issue.title.bold());
        
        if let Some(location) = &issue.location {
            println!("    Location: {}", location.dimmed());
        }
        
        if let Some(context) = &issue.context {
            println!("    Context: {}", context.italic());
        }
        
        if self.verbose {
            println!("    Description: {}", issue.description);
            println!("    Recommendation: {}", issue.recommendation.green());
        }
        
        println!();
    }

    fn display_summary(&self, report: &SecurityReport) {
        println!("{}", "Summary:".bold().underline());
        println!("  Total issues: {}", report.summary.total_issues);
        
        if report.summary.critical_count > 0 {
            println!("  Critical: {}", report.summary.critical_count.to_string().red().bold());
        }
        
        if report.summary.warning_count > 0 {
            println!("  Warnings: {}", report.summary.warning_count.to_string().yellow().bold());
        }
        
        if report.summary.safe_count > 0 {
            println!("  Info: {}", report.summary.safe_count.to_string().blue());
        }

        println!();
        
        match report.overall_level {
            SecurityLevel::Safe => {
                println!("{}", "✓ This package appears to be safe to install.".green().bold());
            }
            SecurityLevel::Warning => {
                println!("{}", "⚠ This package has some security concerns. Review the warnings above.".yellow().bold());
            }
            SecurityLevel::Critical => {
                println!("{}", "✗ This package has critical security issues. Installation is NOT recommended.".red().bold());
            }
        }
    }

    fn display_json_results(&self, report: &SecurityReport) {
        match serde_json::to_string_pretty(report) {
            Ok(json) => println!("{}", json),
            Err(e) => eprintln!("Error serializing report to JSON: {}", e),
        }
    }

}