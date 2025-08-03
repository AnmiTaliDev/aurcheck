use regex::Regex;
use serde::{Deserialize, Serialize};
use lazy_static::lazy_static;

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

pub struct SecurityRules {
    suspicious_commands: Vec<SuspiciousCommand>,
    network_patterns: Vec<NetworkPattern>,
    privilege_patterns: Vec<PrivilegePattern>,
    obfuscation_patterns: Vec<ObfuscationPattern>,
}

#[derive(Debug)]
struct SuspiciousCommand {
    pattern: &'static Regex,
    category: &'static str,
    title: &'static str,
    description: &'static str,
    recommendation: &'static str,
    level: SecurityLevel,
}

#[derive(Debug)]
struct NetworkPattern {
    pattern: &'static Regex,
    category: &'static str,
    title: &'static str,
    description: &'static str,
    recommendation: &'static str,
    level: SecurityLevel,
}

#[derive(Debug)]
struct PrivilegePattern {
    pattern: &'static Regex,
    category: &'static str,
    title: &'static str,
    description: &'static str,
    recommendation: &'static str,
    level: SecurityLevel,
}

#[derive(Debug)]
struct ObfuscationPattern {
    pattern: &'static Regex,
    category: &'static str,
    title: &'static str,
    description: &'static str,
    recommendation: &'static str,
    level: SecurityLevel,
}

// Pre-compiled regex patterns using lazy_static
lazy_static! {
    static ref PYTHON_INLINE: Regex = Regex::new(r"python\s+-c\s+").expect("Invalid regex");
    static ref BASH_INLINE: Regex = Regex::new(r"bash\s+-c\s+").expect("Invalid regex");
    static ref EVAL_PATTERN: Regex = Regex::new(r"eval\s+").expect("Invalid regex");
    static ref BASE64_DECODE: Regex = Regex::new(r"base64\s+(-d|--decode)").expect("Invalid regex");
    static ref ECHO_BASE64: Regex = Regex::new(r"echo\s+[^|]*\|\s*base64\s+(-d|--decode)").expect("Invalid regex");
    static ref CMD_SUBST_BASE64: Regex = Regex::new(r"\$\(.*\|.*base64").expect("Invalid regex");
    static ref HEX_ESCAPE: Regex = Regex::new(r"\\x[0-9a-fA-F]{2}").expect("Invalid regex");
    static ref DD_CONV: Regex = Regex::new(r"dd\s+.*conv=.*").expect("Invalid regex");
    static ref CURL_PIPE_SH: Regex = Regex::new(r"(curl|wget).*\|\s*(sh|bash|zsh)").expect("Invalid regex");
    static ref RM_RECURSIVE_VAR: Regex = Regex::new(r"rm\s+(-rf?|--recursive).*\$\{").expect("Invalid regex");
    static ref FIND_EXEC_RM: Regex = Regex::new(r"find\s+/.*-exec.*rm").expect("Invalid regex");

    static ref HTTP_DOWNLOAD: Regex = Regex::new(r"(curl|wget)\s+.*http://").expect("Invalid regex");
    static ref SHORT_URL: Regex = Regex::new(r"(curl|wget)\s+.*\.(bit\.ly|tinyurl|t\.co|goo\.gl)").expect("Invalid regex");
    static ref DARK_WEB: Regex = Regex::new(r"(curl|wget)\s+.*\.(onion|i2p)").expect("Invalid regex");
    static ref INSECURE_K: Regex = Regex::new(r"(curl|wget).*-k\s+").expect("Invalid regex");
    static ref INSECURE_FLAG: Regex = Regex::new(r"(curl|wget).*--insecure").expect("Invalid regex");
    static ref NETCAT_EXEC: Regex = Regex::new(r"nc\s+.*-e\s+").expect("Invalid regex");
    static ref SOCAT_EXEC: Regex = Regex::new(r"socat\s+.*EXEC").expect("Invalid regex");

    static ref SUDO_PATTERN: Regex = Regex::new(r"sudo\s+").expect("Invalid regex");
    static ref CHMOD_SUSPECT: Regex = Regex::new(r"chmod\s+[0-7]*[4-7][0-7]*\s+").expect("Invalid regex");
    static ref CHOWN_ROOT: Regex = Regex::new(r"chown\s+root").expect("Invalid regex");
    static ref SU_COMMAND: Regex = Regex::new(r"su\s+-c").expect("Invalid regex");
    static ref PKEXEC_PATTERN: Regex = Regex::new(r"pkexec\s+").expect("Invalid regex");
    static ref GKSUDO_PATTERN: Regex = Regex::new(r"gksudo\s+").expect("Invalid regex");

    static ref PARAM_SUBST: Regex = Regex::new(r"\$\{[^}]*[#%][^}]*\}").expect("Invalid regex");
    static ref TR_PATTERN: Regex = Regex::new(r"tr\s+").expect("Invalid regex");
    static ref REV_PATTERN: Regex = Regex::new(r"rev\s+").expect("Invalid regex");
    static ref OD_HEX: Regex = Regex::new(r"od\s+(-A\s*n)?.*-t\s*x").expect("Invalid regex");
    static ref XXD_REVERT: Regex = Regex::new(r"xxd\s+(-r|-revert)").expect("Invalid regex");
    static ref ARITHMETIC_OBFUSC: Regex = Regex::new(r"\$(\(|\[).*[+\-*/].*(\)|\])").expect("Invalid regex");
    static ref ADV_PARAM_SUBST: Regex = Regex::new(r"\$\{[^}]*//.*[\$`\(][^}]*\}").expect("Invalid regex");
}

impl SecurityRules {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let suspicious_commands = vec![
            SuspiciousCommand {
                pattern: &PYTHON_INLINE,
                category: "Suspicious Commands",
                title: "Python inline execution",
                description: "Package executes Python code inline, which can be used to hide malicious activity",
                recommendation: "Review the Python code being executed for suspicious activity",
                level: SecurityLevel::Warning,
            },
            SuspiciousCommand {
                pattern: &BASH_INLINE,
                category: "Suspicious Commands",
                title: "Bash inline execution",
                description: "Package executes bash commands inline, potentially hiding malicious commands",
                recommendation: "Review the bash commands being executed",
                level: SecurityLevel::Warning,
            },
            SuspiciousCommand {
                pattern: &EVAL_PATTERN,
                category: "Suspicious Commands",
                title: "Dynamic code evaluation",
                description: "Package uses eval to execute dynamic code, which is dangerous",
                recommendation: "Avoid using eval or carefully review the code being evaluated",
                level: SecurityLevel::Critical,
            },
            SuspiciousCommand {
                pattern: &BASE64_DECODE,
                category: "Obfuscation",
                title: "Base64 decoding detected",
                description: "Package decodes base64 content, which may hide malicious payloads",
                recommendation: "Inspect what is being decoded and verify its safety",
                level: SecurityLevel::Warning,
            },
            SuspiciousCommand {
                pattern: &ECHO_BASE64,
                category: "Obfuscation",
                title: "Inline base64 decode pipeline",
                description: "Package uses echo|base64 pipeline to decode hidden content",
                recommendation: "Decode the base64 content manually and verify its safety",
                level: SecurityLevel::Critical,
            },
            SuspiciousCommand {
                pattern: &CMD_SUBST_BASE64,
                category: "Obfuscation",
                title: "Command substitution with base64",
                description: "Package uses command substitution with base64 encoding/decoding",
                recommendation: "Manually execute the command substitution to see what's being processed",
                level: SecurityLevel::Critical,
            },
            SuspiciousCommand {
                pattern: &HEX_ESCAPE,
                category: "Obfuscation",
                title: "Hexadecimal escape sequences",
                description: "Package contains hexadecimal escape sequences that may hide commands",
                recommendation: "Decode the hex sequences to see the actual content",
                level: SecurityLevel::Warning,
            },
            SuspiciousCommand {
                pattern: &DD_CONV,
                category: "Suspicious Commands",
                title: "DD with conversion",
                description: "Package uses dd with conversion which can be used for obfuscation",
                recommendation: "Review what data is being converted and why",
                level: SecurityLevel::Warning,
            },
            SuspiciousCommand {
                pattern: &CURL_PIPE_SH,
                category: "Network Security",
                title: "Download and execute pipeline",
                description: "Package downloads content and directly pipes it to shell execution",
                recommendation: "Download the content separately and inspect it before execution",
                level: SecurityLevel::Critical,
            },
            SuspiciousCommand {
                pattern: &RM_RECURSIVE_VAR,
                category: "Dangerous Operations",
                title: "Recursive delete with variables",
                description: "Package performs recursive deletion using shell variables",
                recommendation: "Verify the variables contain safe paths before execution",
                level: SecurityLevel::Critical,
            },
            SuspiciousCommand {
                pattern: &FIND_EXEC_RM,
                category: "Dangerous Operations",
                title: "Find and delete pattern",
                description: "Package uses find to locate and delete files system-wide",
                recommendation: "Review what files are being targeted for deletion",
                level: SecurityLevel::Warning,
            },
        ];

        let network_patterns = vec![
            NetworkPattern {
                pattern: &HTTP_DOWNLOAD,
                category: "Network Security",
                title: "Insecure HTTP download",
                description: "Package downloads files over insecure HTTP connection",
                recommendation: "Use HTTPS instead of HTTP for secure downloads",
                level: SecurityLevel::Warning,
            },
            NetworkPattern {
                pattern: &SHORT_URL,
                category: "Network Security",
                title: "Suspicious short URL",
                description: "Package downloads from URL shortener, hiding the real destination",
                recommendation: "Expand the shortened URL and verify the destination is safe",
                level: SecurityLevel::Critical,
            },
            NetworkPattern {
                pattern: &DARK_WEB,
                category: "Network Security",
                title: "Dark web download",
                description: "Package downloads from dark web (.onion/.i2p) address",
                recommendation: "Investigate why the package needs to access dark web resources",
                level: SecurityLevel::Critical,
            },
            NetworkPattern {
                pattern: &INSECURE_K,
                category: "Network Security",
                title: "Insecure TLS download",
                description: "Package downloads with TLS certificate verification disabled",
                recommendation: "Remove -k flag to enable proper certificate verification",
                level: SecurityLevel::Critical,
            },
            NetworkPattern {
                pattern: &INSECURE_FLAG,
                category: "Network Security",
                title: "Explicitly insecure download",
                description: "Package explicitly disables security checks for downloads",
                recommendation: "Remove --insecure flag and ensure proper TLS verification",
                level: SecurityLevel::Critical,
            },
            NetworkPattern {
                pattern: &NETCAT_EXEC,
                category: "Network Security",
                title: "Netcat with command execution",
                description: "Package uses netcat to execute commands over network",
                recommendation: "Verify this network communication is necessary and secure",
                level: SecurityLevel::Critical,
            },
            NetworkPattern {
                pattern: &SOCAT_EXEC,
                category: "Network Security",
                title: "Socat command execution",
                description: "Package uses socat to execute commands over network connections",
                recommendation: "Review the network communication and command execution",
                level: SecurityLevel::Critical,
            },
        ];

        let privilege_patterns = vec![
            PrivilegePattern {
                pattern: &SUDO_PATTERN,
                category: "Privilege Escalation",
                title: "Sudo usage detected",
                description: "Package attempts to use sudo for privilege escalation",
                recommendation: "Verify that sudo usage is necessary and properly justified",
                level: SecurityLevel::Warning,
            },
            PrivilegePattern {
                pattern: &CHMOD_SUSPECT,
                category: "Privilege Escalation",
                title: "Suspicious file permissions",
                description: "Package sets suspicious file permissions (setuid/setgid)",
                recommendation: "Review why special permissions are needed",
                level: SecurityLevel::Critical,
            },
            PrivilegePattern {
                pattern: &CHOWN_ROOT,
                category: "Privilege Escalation",
                title: "Root ownership change",
                description: "Package changes file ownership to root",
                recommendation: "Verify that root ownership is necessary and justified",
                level: SecurityLevel::Warning,
            },
            PrivilegePattern {
                pattern: &SU_COMMAND,
                category: "Privilege Escalation",
                title: "Switch user command execution",
                description: "Package uses su to execute commands as different user",
                recommendation: "Verify the user switch is necessary and commands are safe",
                level: SecurityLevel::Warning,
            },
            PrivilegePattern {
                pattern: &PKEXEC_PATTERN,
                category: "Privilege Escalation",
                title: "PolicyKit execution",
                description: "Package uses pkexec for privilege escalation",
                recommendation: "Verify PolicyKit usage is necessary and properly configured",
                level: SecurityLevel::Warning,
            },
            PrivilegePattern {
                pattern: &GKSUDO_PATTERN,
                category: "Privilege Escalation",
                title: "Graphical sudo execution",
                description: "Package uses gksudo for graphical privilege escalation",
                recommendation: "Verify graphical sudo is necessary for the operation",
                level: SecurityLevel::Warning,
            },
        ];

        let obfuscation_patterns = vec![
            ObfuscationPattern {
                pattern: &PARAM_SUBST,
                category: "Obfuscation",
                title: "Shell parameter substitution",
                description: "Package uses shell parameter substitution which may obfuscate commands",
                recommendation: "Manually expand the parameter substitution to see actual commands",
                level: SecurityLevel::Warning,
            },
            ObfuscationPattern {
                pattern: &TR_PATTERN,
                category: "Obfuscation",
                title: "Character translation",
                description: "Package uses tr command which may be used to obfuscate text",
                recommendation: "Review what text transformations are being performed",
                level: SecurityLevel::Warning,
            },
            ObfuscationPattern {
                pattern: &REV_PATTERN,
                category: "Obfuscation",
                title: "Text reversal",
                description: "Package uses rev command to reverse text, possibly for obfuscation",
                recommendation: "Check what text is being reversed and why",
                level: SecurityLevel::Warning,
            },
            ObfuscationPattern {
                pattern: &OD_HEX,
                category: "Obfuscation",
                title: "Octal dump hex conversion",
                description: "Package uses od to convert data to hexadecimal, possibly for obfuscation",
                recommendation: "Review what data is being converted and verify its purpose",
                level: SecurityLevel::Warning,
            },
            ObfuscationPattern {
                pattern: &XXD_REVERT,
                category: "Obfuscation",
                title: "Hex dump reversal",
                description: "Package uses xxd to reverse hex dumps back to binary",
                recommendation: "Examine what hex data is being converted back to binary",
                level: SecurityLevel::Warning,
            },
            ObfuscationPattern {
                pattern: &ARITHMETIC_OBFUSC,
                category: "Obfuscation",
                title: "Arithmetic obfuscation",
                description: "Package uses arithmetic expressions that may obfuscate values",
                recommendation: "Calculate the arithmetic expressions to see actual values",
                level: SecurityLevel::Warning,
            },
            ObfuscationPattern {
                pattern: &ADV_PARAM_SUBST,
                category: "Obfuscation",
                title: "Advanced parameter substitution",
                description: "Package uses advanced shell parameter substitution for replacement",
                recommendation: "Manually expand the parameter substitution to see the result",
                level: SecurityLevel::Warning,
            },
        ];

        Ok(Self {
            suspicious_commands,
            network_patterns,
            privilege_patterns,
            obfuscation_patterns,
        })
    }

    pub fn check_content(&self, content: &str, location: &str) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();

        for rule in &self.suspicious_commands {
            if let Some(matched) = rule.pattern.find(content) {
                issues.push(SecurityIssue {
                    level: rule.level.clone(),
                    category: rule.category.to_string(),
                    title: rule.title.to_string(),
                    description: rule.description.to_string(),
                    recommendation: rule.recommendation.to_string(),
                    location: Some(location.to_string()),
                    context: Some(matched.as_str().to_string()),
                });
            }
        }

        for rule in &self.network_patterns {
            if let Some(matched) = rule.pattern.find(content) {
                issues.push(SecurityIssue {
                    level: rule.level.clone(),
                    category: rule.category.to_string(),
                    title: rule.title.to_string(),
                    description: rule.description.to_string(),
                    recommendation: rule.recommendation.to_string(),
                    location: Some(location.to_string()),
                    context: Some(matched.as_str().to_string()),
                });
            }
        }

        for rule in &self.privilege_patterns {
            if let Some(matched) = rule.pattern.find(content) {
                issues.push(SecurityIssue {
                    level: rule.level.clone(),
                    category: rule.category.to_string(),
                    title: rule.title.to_string(),
                    description: rule.description.to_string(),
                    recommendation: rule.recommendation.to_string(),
                    location: Some(location.to_string()),
                    context: Some(matched.as_str().to_string()),
                });
            }
        }

        for rule in &self.obfuscation_patterns {
            if let Some(matched) = rule.pattern.find(content) {
                issues.push(SecurityIssue {
                    level: rule.level.clone(),
                    category: rule.category.to_string(),
                    title: rule.title.to_string(),
                    description: rule.description.to_string(),
                    recommendation: rule.recommendation.to_string(),
                    location: Some(location.to_string()),
                    context: Some(matched.as_str().to_string()),
                });
            }
        }

        issues
    }
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