use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use crate::security::{SecurityIssue, SecurityLevel};
use crate::pkgbuild::PkgBuild;

// ============================================================================
// BEHAVIOR CATEGORIES AND ACTIONS
// ============================================================================

/// What a command fundamentally DOES, not how it looks
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BehaviorCategory {
    Network,
    Filesystem,
    Privilege,
    CodeExecution,
    DataObfuscation,
    SystemModification,
    PackageManagement,
    EnvironmentManipulation,
    UserManagement,
    KernelOperations,
    Benign,
}

impl BehaviorCategory {
    /// Base risk score for each behavior category (0-100)
    pub fn base_risk(&self) -> u32 {
        match self {
            BehaviorCategory::KernelOperations => 80,
            BehaviorCategory::CodeExecution => 70,
            BehaviorCategory::Privilege => 60,
            BehaviorCategory::SystemModification => 50,
            BehaviorCategory::DataObfuscation => 40,
            BehaviorCategory::EnvironmentManipulation => 35,
            BehaviorCategory::Network => 30,
            BehaviorCategory::PackageManagement => 25,
            BehaviorCategory::Filesystem => 20,
            BehaviorCategory::UserManagement => 55,
            BehaviorCategory::Benign => 0,
        }
    }
}

/// Specific action within a behavior category
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ActionType {
    // Network actions
    Download,
    Upload,
    ReverseShell,
    DnsLookup,
    RawSocket,

    // Filesystem actions
    Write,
    Delete,
    ModifyPermissions,
    CreateSymlink,
    MountFilesystem,

    // Privilege actions
    Sudo,
    Setuid,
    CapabilityChange,
    SwitchUser,

    // Code execution actions
    Eval,
    Source,
    PipeToInterpreter,
    DynamicLoad,
    InlineExecution,

    // Obfuscation actions
    Base64Decode,
    HexDecode,
    Encryption,
    StringReversal,
    CharacterSubstitution,

    // System modification actions
    ServiceControl,
    CronJob,
    StartupScript,
    SystemdUnit,

    // Generic
    Unknown,
}

impl ActionType {
    /// Action-specific risk modifier (multiplier, addition)
    pub fn risk_modifier(&self) -> (f32, i32) {
        match self {
            // Network - high risk for certain actions
            ActionType::Download => (1.0, 0),
            ActionType::Upload => (1.5, 20),
            ActionType::ReverseShell => (3.0, 100),
            ActionType::DnsLookup => (0.5, 0),
            ActionType::RawSocket => (2.0, 30),

            // Filesystem
            ActionType::Write => (1.0, 0),
            ActionType::Delete => (1.5, 10),
            ActionType::ModifyPermissions => (1.2, 15),
            ActionType::CreateSymlink => (0.8, 5),
            ActionType::MountFilesystem => (2.0, 30),

            // Privilege
            ActionType::Sudo => (1.5, 20),
            ActionType::Setuid => (2.5, 50),
            ActionType::CapabilityChange => (2.0, 40),
            ActionType::SwitchUser => (1.3, 15),

            // Code execution
            ActionType::Eval => (2.0, 40),
            ActionType::Source => (1.5, 20),
            ActionType::PipeToInterpreter => (2.5, 50),
            ActionType::DynamicLoad => (1.8, 30),
            ActionType::InlineExecution => (1.5, 25),

            // Obfuscation
            ActionType::Base64Decode => (1.3, 15),
            ActionType::HexDecode => (1.3, 15),
            ActionType::Encryption => (1.5, 20),
            ActionType::StringReversal => (1.4, 10),
            ActionType::CharacterSubstitution => (1.2, 10),

            // System modification
            ActionType::ServiceControl => (1.5, 20),
            ActionType::CronJob => (2.0, 40),
            ActionType::StartupScript => (2.0, 40),
            ActionType::SystemdUnit => (1.8, 35),

            ActionType::Unknown => (1.0, 0),
        }
    }
}

// ============================================================================
// BEHAVIOR ACTION
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorAction {
    pub category: BehaviorCategory,
    pub action_type: ActionType,
    pub base_risk: u32,
    pub description: String,
}

// ============================================================================
// COMMAND CONTEXT
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FunctionType {
    Prepare,
    Build,
    Check,
    Package,
    PreInstall,
    PostInstall,
    PreRemove,
    PostRemove,
    PreUpgrade,
    PostUpgrade,
    Global,
    Unknown,
}

impl FunctionType {
    pub fn from_name(name: &str) -> Self {
        match name {
            "prepare" => FunctionType::Prepare,
            "build" => FunctionType::Build,
            "check" => FunctionType::Check,
            "package" | "package_" => FunctionType::Package,
            "pre_install" => FunctionType::PreInstall,
            "post_install" => FunctionType::PostInstall,
            "pre_remove" => FunctionType::PreRemove,
            "post_remove" => FunctionType::PostRemove,
            "pre_upgrade" => FunctionType::PreUpgrade,
            "post_upgrade" => FunctionType::PostUpgrade,
            _ if name.starts_with("package_") => FunctionType::Package,
            _ => FunctionType::Unknown,
        }
    }

    /// Context score adjustment for function type
    pub fn context_adjustment(&self) -> i32 {
        match self {
            FunctionType::Prepare => 0,
            FunctionType::Build => 0,
            FunctionType::Check => -20,
            FunctionType::Package => 10,
            FunctionType::PreInstall => 50,
            FunctionType::PostInstall => 50,
            FunctionType::PreRemove => 40,
            FunctionType::PostRemove => 40,
            FunctionType::PreUpgrade => 45,
            FunctionType::PostUpgrade => 45,
            FunctionType::Global => 20,
            FunctionType::Unknown => 10,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandContext {
    pub function_name: Option<String>,
    pub function_type: FunctionType,
    pub is_in_conditional: bool,
    pub is_in_loop: bool,
    pub is_in_subshell: bool,
    pub is_in_comment: bool,
    pub is_in_string: bool,
    pub line_number: usize,
}

impl Default for CommandContext {
    fn default() -> Self {
        Self {
            function_name: None,
            function_type: FunctionType::Global,
            is_in_conditional: false,
            is_in_loop: false,
            is_in_subshell: false,
            is_in_comment: false,
            is_in_string: false,
            line_number: 0,
        }
    }
}

impl CommandContext {
    /// Calculate context-based score adjustment
    pub fn calculate_adjustment(&self) -> i32 {
        let mut adjustment: i32 = 0;

        // Function type adjustment
        adjustment += self.function_type.context_adjustment();

        // Context modifiers
        if self.is_in_comment {
            adjustment -= 200; // Strong reduction - it's just a comment
        }

        if self.is_in_string {
            adjustment -= 50; // Might be documentation
        }

        if self.is_in_conditional {
            adjustment -= 10; // Controlled execution
        }

        if self.is_in_subshell {
            adjustment += 15; // Dynamic execution
        }

        adjustment
    }
}

// ============================================================================
// ARGUMENT CLASSIFICATION
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArgumentType {
    Flag,
    Path,
    Url,
    Variable,
    Literal,
    Command,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandArgument {
    pub value: String,
    pub arg_type: ArgumentType,
    pub is_user_controlled: bool,
}

// ============================================================================
// PARSED COMMAND
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedCommand {
    pub raw_text: String,
    pub command_name: String,
    pub arguments: Vec<CommandArgument>,
    pub behaviors: Vec<BehaviorAction>,
    pub context: CommandContext,
}

// ============================================================================
// RISK SCORING
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScore {
    pub total_score: u32,
    pub base_score: u32,
    pub context_score: i32,
    pub combination_score: u32,
    pub source_trust_score: i32,
    pub confidence: f32,
}

impl RiskScore {
    pub fn zero() -> Self {
        Self {
            total_score: 0,
            base_score: 0,
            context_score: 0,
            combination_score: 0,
            source_trust_score: 0,
            confidence: 1.0,
        }
    }
}

/// Risk level thresholds
#[derive(Debug, Clone)]
pub struct RiskThresholds {
    pub safe_max: u32,
    pub warning_max: u32,
}

impl Default for RiskThresholds {
    fn default() -> Self {
        Self {
            safe_max: 50,
            warning_max: 150,
        }
    }
}

impl RiskScore {
    pub fn to_security_level(&self, thresholds: &RiskThresholds) -> SecurityLevel {
        let adjusted_score = (self.total_score as f32 * self.confidence) as u32;

        if adjusted_score <= thresholds.safe_max {
            SecurityLevel::Safe
        } else if adjusted_score <= thresholds.warning_max {
            SecurityLevel::Warning
        } else {
            SecurityLevel::Critical
        }
    }
}

// ============================================================================
// SOURCE TRUST SCORING
// ============================================================================

pub struct SourceTrustScorer;

impl SourceTrustScorer {
    pub fn score_url(url: &str) -> i32 {
        let mut adjustment: i32 = 0;

        // Protocol trust
        if url.starts_with("http://") {
            adjustment -= 30;
        } else if url.starts_with("https://") {
            adjustment += 10;
        } else if url.starts_with("git://") {
            adjustment -= 20;
        } else if url.starts_with("git+https://") {
            adjustment += 5;
        }

        // Known trusted domains
        let trusted_domains = [
            "github.com", "gitlab.com", "bitbucket.org",
            "kernel.org", "gnu.org", "freedesktop.org",
            "archlinux.org", "sourceforge.net", "crates.io",
            "pypi.org", "npmjs.com", "rubygems.org",
        ];

        if trusted_domains.iter().any(|d| url.contains(d)) {
            adjustment += 20;
        }

        // Suspicious domains
        let suspicious_indicators = [
            "pastebin.com", "hastebin.com", "paste.ee",
            ".tk", ".ml", ".ga", ".cf", ".gq",
            "dyndns", "no-ip", "ddns",
        ];

        if suspicious_indicators.iter().any(|d| url.contains(d)) {
            adjustment -= 50;
        }

        // URL shorteners
        let shorteners = [
            "bit.ly", "tinyurl", "t.co", "goo.gl",
            "ow.ly", "is.gd", "v.gd",
        ];

        if shorteners.iter().any(|d| url.contains(d)) {
            adjustment -= 80;
        }

        // Dark web
        if url.contains(".onion") || url.contains(".i2p") {
            adjustment -= 150;
        }

        adjustment
    }
}

// ============================================================================
// COMBINATION PATTERNS
// ============================================================================

#[derive(Debug, Clone)]
pub struct CombinationPattern {
    pub name: String,
    pub description: String,
    pub required_behaviors: Vec<(BehaviorCategory, ActionType)>,
    pub proximity_lines: usize,
    pub bonus_score: u32,
    pub is_sequential: bool,
}

impl CombinationPattern {
    pub fn dangerous_patterns() -> Vec<Self> {
        vec![
            // Download + Execute pattern
            CombinationPattern {
                name: "download_execute".into(),
                description: "Downloads content and executes it".into(),
                required_behaviors: vec![
                    (BehaviorCategory::Network, ActionType::Download),
                    (BehaviorCategory::CodeExecution, ActionType::PipeToInterpreter),
                ],
                proximity_lines: 1,
                bonus_score: 150,
                is_sequential: true,
            },
            // Obfuscate + Execute pattern
            CombinationPattern {
                name: "decode_execute".into(),
                description: "Decodes obfuscated content and executes it".into(),
                required_behaviors: vec![
                    (BehaviorCategory::DataObfuscation, ActionType::Base64Decode),
                    (BehaviorCategory::CodeExecution, ActionType::Eval),
                ],
                proximity_lines: 3,
                bonus_score: 120,
                is_sequential: true,
            },
            // Privilege + System modification
            CombinationPattern {
                name: "privilege_system_mod".into(),
                description: "Escalates privileges then modifies system".into(),
                required_behaviors: vec![
                    (BehaviorCategory::Privilege, ActionType::Sudo),
                    (BehaviorCategory::SystemModification, ActionType::CronJob),
                ],
                proximity_lines: 5,
                bonus_score: 80,
                is_sequential: false,
            },
            // Network + Privilege escalation
            CombinationPattern {
                name: "remote_privilege".into(),
                description: "Network activity combined with privilege escalation".into(),
                required_behaviors: vec![
                    (BehaviorCategory::Network, ActionType::Download),
                    (BehaviorCategory::Privilege, ActionType::Sudo),
                ],
                proximity_lines: 10,
                bonus_score: 60,
                is_sequential: false,
            },
        ]
    }
}

// ============================================================================
// COMMAND DATABASE
// ============================================================================

#[derive(Debug, Clone)]
pub struct CommandBehavior {
    pub command: String,
    pub default_behaviors: Vec<BehaviorAction>,
    pub flag_behaviors: HashMap<String, Vec<BehaviorAction>>,
}

pub struct CommandDatabase {
    commands: HashMap<String, CommandBehavior>,
}

impl CommandDatabase {
    pub fn new() -> Self {
        let mut commands = HashMap::new();

        // Network commands
        Self::add_network_commands(&mut commands);

        // Code execution commands
        Self::add_code_execution_commands(&mut commands);

        // Obfuscation commands
        Self::add_obfuscation_commands(&mut commands);

        // Privilege commands
        Self::add_privilege_commands(&mut commands);

        // Filesystem commands
        Self::add_filesystem_commands(&mut commands);

        // System modification commands
        Self::add_system_commands(&mut commands);

        Self { commands }
    }

    fn add_network_commands(commands: &mut HashMap<String, CommandBehavior>) {
        commands.insert("curl".to_string(), CommandBehavior {
            command: "curl".to_string(),
            default_behaviors: vec![
                BehaviorAction {
                    category: BehaviorCategory::Network,
                    action_type: ActionType::Download,
                    base_risk: 30,
                    description: "HTTP client download".into(),
                }
            ],
            flag_behaviors: HashMap::from([
                ("-k".to_string(), vec![BehaviorAction {
                    category: BehaviorCategory::Network,
                    action_type: ActionType::Download,
                    base_risk: 60,
                    description: "Insecure TLS download (certificate verification disabled)".into(),
                }]),
                ("--insecure".to_string(), vec![BehaviorAction {
                    category: BehaviorCategory::Network,
                    action_type: ActionType::Download,
                    base_risk: 60,
                    description: "Insecure TLS download".into(),
                }]),
                ("-T".to_string(), vec![BehaviorAction {
                    category: BehaviorCategory::Network,
                    action_type: ActionType::Upload,
                    base_risk: 50,
                    description: "Data upload/exfiltration".into(),
                }]),
                ("--upload-file".to_string(), vec![BehaviorAction {
                    category: BehaviorCategory::Network,
                    action_type: ActionType::Upload,
                    base_risk: 50,
                    description: "Data upload/exfiltration".into(),
                }]),
            ]),
        });

        commands.insert("wget".to_string(), CommandBehavior {
            command: "wget".to_string(),
            default_behaviors: vec![
                BehaviorAction {
                    category: BehaviorCategory::Network,
                    action_type: ActionType::Download,
                    base_risk: 30,
                    description: "HTTP download".into(),
                }
            ],
            flag_behaviors: HashMap::from([
                ("--no-check-certificate".to_string(), vec![BehaviorAction {
                    category: BehaviorCategory::Network,
                    action_type: ActionType::Download,
                    base_risk: 60,
                    description: "Insecure download (certificate verification disabled)".into(),
                }]),
            ]),
        });

        commands.insert("nc".to_string(), CommandBehavior {
            command: "nc".to_string(),
            default_behaviors: vec![
                BehaviorAction {
                    category: BehaviorCategory::Network,
                    action_type: ActionType::RawSocket,
                    base_risk: 50,
                    description: "Raw network socket communication".into(),
                }
            ],
            flag_behaviors: HashMap::from([
                ("-e".to_string(), vec![BehaviorAction {
                    category: BehaviorCategory::Network,
                    action_type: ActionType::ReverseShell,
                    base_risk: 90,
                    description: "Netcat with command execution (potential reverse shell)".into(),
                }]),
            ]),
        });

        commands.insert("socat".to_string(), CommandBehavior {
            command: "socat".to_string(),
            default_behaviors: vec![
                BehaviorAction {
                    category: BehaviorCategory::Network,
                    action_type: ActionType::RawSocket,
                    base_risk: 50,
                    description: "Socket relay".into(),
                }
            ],
            flag_behaviors: HashMap::new(),
        });
    }

    fn add_code_execution_commands(commands: &mut HashMap<String, CommandBehavior>) {
        commands.insert("eval".to_string(), CommandBehavior {
            command: "eval".to_string(),
            default_behaviors: vec![
                BehaviorAction {
                    category: BehaviorCategory::CodeExecution,
                    action_type: ActionType::Eval,
                    base_risk: 70,
                    description: "Dynamic code evaluation".into(),
                }
            ],
            flag_behaviors: HashMap::new(),
        });

        commands.insert("bash".to_string(), CommandBehavior {
            command: "bash".to_string(),
            default_behaviors: vec![],
            flag_behaviors: HashMap::from([
                ("-c".to_string(), vec![BehaviorAction {
                    category: BehaviorCategory::CodeExecution,
                    action_type: ActionType::InlineExecution,
                    base_risk: 50,
                    description: "Inline bash command execution".into(),
                }]),
            ]),
        });

        commands.insert("sh".to_string(), CommandBehavior {
            command: "sh".to_string(),
            default_behaviors: vec![],
            flag_behaviors: HashMap::from([
                ("-c".to_string(), vec![BehaviorAction {
                    category: BehaviorCategory::CodeExecution,
                    action_type: ActionType::InlineExecution,
                    base_risk: 50,
                    description: "Inline shell command execution".into(),
                }]),
            ]),
        });

        commands.insert("python".to_string(), CommandBehavior {
            command: "python".to_string(),
            default_behaviors: vec![],
            flag_behaviors: HashMap::from([
                ("-c".to_string(), vec![BehaviorAction {
                    category: BehaviorCategory::CodeExecution,
                    action_type: ActionType::InlineExecution,
                    base_risk: 50,
                    description: "Inline Python execution".into(),
                }]),
            ]),
        });

        commands.insert("python3".to_string(), CommandBehavior {
            command: "python3".to_string(),
            default_behaviors: vec![],
            flag_behaviors: HashMap::from([
                ("-c".to_string(), vec![BehaviorAction {
                    category: BehaviorCategory::CodeExecution,
                    action_type: ActionType::InlineExecution,
                    base_risk: 50,
                    description: "Inline Python3 execution".into(),
                }]),
            ]),
        });

        commands.insert("perl".to_string(), CommandBehavior {
            command: "perl".to_string(),
            default_behaviors: vec![],
            flag_behaviors: HashMap::from([
                ("-e".to_string(), vec![BehaviorAction {
                    category: BehaviorCategory::CodeExecution,
                    action_type: ActionType::InlineExecution,
                    base_risk: 50,
                    description: "Inline Perl execution".into(),
                }]),
            ]),
        });

        commands.insert("ruby".to_string(), CommandBehavior {
            command: "ruby".to_string(),
            default_behaviors: vec![],
            flag_behaviors: HashMap::from([
                ("-e".to_string(), vec![BehaviorAction {
                    category: BehaviorCategory::CodeExecution,
                    action_type: ActionType::InlineExecution,
                    base_risk: 50,
                    description: "Inline Ruby execution".into(),
                }]),
            ]),
        });

        commands.insert("source".to_string(), CommandBehavior {
            command: "source".to_string(),
            default_behaviors: vec![
                BehaviorAction {
                    category: BehaviorCategory::CodeExecution,
                    action_type: ActionType::Source,
                    base_risk: 40,
                    description: "Sourcing external script".into(),
                }
            ],
            flag_behaviors: HashMap::new(),
        });

        commands.insert(".".to_string(), CommandBehavior {
            command: ".".to_string(),
            default_behaviors: vec![
                BehaviorAction {
                    category: BehaviorCategory::CodeExecution,
                    action_type: ActionType::Source,
                    base_risk: 40,
                    description: "Sourcing external script (dot command)".into(),
                }
            ],
            flag_behaviors: HashMap::new(),
        });
    }

    fn add_obfuscation_commands(commands: &mut HashMap<String, CommandBehavior>) {
        commands.insert("base64".to_string(), CommandBehavior {
            command: "base64".to_string(),
            default_behaviors: vec![],
            flag_behaviors: HashMap::from([
                ("-d".to_string(), vec![BehaviorAction {
                    category: BehaviorCategory::DataObfuscation,
                    action_type: ActionType::Base64Decode,
                    base_risk: 40,
                    description: "Base64 decoding".into(),
                }]),
                ("--decode".to_string(), vec![BehaviorAction {
                    category: BehaviorCategory::DataObfuscation,
                    action_type: ActionType::Base64Decode,
                    base_risk: 40,
                    description: "Base64 decoding".into(),
                }]),
            ]),
        });

        commands.insert("xxd".to_string(), CommandBehavior {
            command: "xxd".to_string(),
            default_behaviors: vec![],
            flag_behaviors: HashMap::from([
                ("-r".to_string(), vec![BehaviorAction {
                    category: BehaviorCategory::DataObfuscation,
                    action_type: ActionType::HexDecode,
                    base_risk: 40,
                    description: "Hex dump reversal".into(),
                }]),
                ("--revert".to_string(), vec![BehaviorAction {
                    category: BehaviorCategory::DataObfuscation,
                    action_type: ActionType::HexDecode,
                    base_risk: 40,
                    description: "Hex dump reversal".into(),
                }]),
            ]),
        });

        commands.insert("tr".to_string(), CommandBehavior {
            command: "tr".to_string(),
            default_behaviors: vec![
                BehaviorAction {
                    category: BehaviorCategory::DataObfuscation,
                    action_type: ActionType::CharacterSubstitution,
                    base_risk: 20,
                    description: "Character translation (may be obfuscation)".into(),
                }
            ],
            flag_behaviors: HashMap::new(),
        });

        commands.insert("rev".to_string(), CommandBehavior {
            command: "rev".to_string(),
            default_behaviors: vec![
                BehaviorAction {
                    category: BehaviorCategory::DataObfuscation,
                    action_type: ActionType::StringReversal,
                    base_risk: 30,
                    description: "String reversal (potential obfuscation)".into(),
                }
            ],
            flag_behaviors: HashMap::new(),
        });

        commands.insert("od".to_string(), CommandBehavior {
            command: "od".to_string(),
            default_behaviors: vec![],
            flag_behaviors: HashMap::from([
                ("-x".to_string(), vec![BehaviorAction {
                    category: BehaviorCategory::DataObfuscation,
                    action_type: ActionType::HexDecode,
                    base_risk: 30,
                    description: "Octal dump to hex".into(),
                }]),
            ]),
        });
    }

    fn add_privilege_commands(commands: &mut HashMap<String, CommandBehavior>) {
        commands.insert("sudo".to_string(), CommandBehavior {
            command: "sudo".to_string(),
            default_behaviors: vec![
                BehaviorAction {
                    category: BehaviorCategory::Privilege,
                    action_type: ActionType::Sudo,
                    base_risk: 60,
                    description: "Privilege escalation via sudo".into(),
                }
            ],
            flag_behaviors: HashMap::new(),
        });

        commands.insert("su".to_string(), CommandBehavior {
            command: "su".to_string(),
            default_behaviors: vec![
                BehaviorAction {
                    category: BehaviorCategory::Privilege,
                    action_type: ActionType::SwitchUser,
                    base_risk: 50,
                    description: "User switch".into(),
                }
            ],
            flag_behaviors: HashMap::from([
                ("-c".to_string(), vec![BehaviorAction {
                    category: BehaviorCategory::Privilege,
                    action_type: ActionType::SwitchUser,
                    base_risk: 60,
                    description: "User switch with command execution".into(),
                }]),
            ]),
        });

        commands.insert("pkexec".to_string(), CommandBehavior {
            command: "pkexec".to_string(),
            default_behaviors: vec![
                BehaviorAction {
                    category: BehaviorCategory::Privilege,
                    action_type: ActionType::Sudo,
                    base_risk: 60,
                    description: "PolicyKit privilege escalation".into(),
                }
            ],
            flag_behaviors: HashMap::new(),
        });

        commands.insert("gksudo".to_string(), CommandBehavior {
            command: "gksudo".to_string(),
            default_behaviors: vec![
                BehaviorAction {
                    category: BehaviorCategory::Privilege,
                    action_type: ActionType::Sudo,
                    base_risk: 60,
                    description: "Graphical sudo".into(),
                }
            ],
            flag_behaviors: HashMap::new(),
        });

        commands.insert("chmod".to_string(), CommandBehavior {
            command: "chmod".to_string(),
            default_behaviors: vec![
                BehaviorAction {
                    category: BehaviorCategory::Filesystem,
                    action_type: ActionType::ModifyPermissions,
                    base_risk: 20,
                    description: "Permission modification".into(),
                }
            ],
            flag_behaviors: HashMap::new(),
        });

        commands.insert("chown".to_string(), CommandBehavior {
            command: "chown".to_string(),
            default_behaviors: vec![
                BehaviorAction {
                    category: BehaviorCategory::Filesystem,
                    action_type: ActionType::ModifyPermissions,
                    base_risk: 25,
                    description: "Ownership modification".into(),
                }
            ],
            flag_behaviors: HashMap::new(),
        });
    }

    fn add_filesystem_commands(commands: &mut HashMap<String, CommandBehavior>) {
        commands.insert("rm".to_string(), CommandBehavior {
            command: "rm".to_string(),
            default_behaviors: vec![
                BehaviorAction {
                    category: BehaviorCategory::Filesystem,
                    action_type: ActionType::Delete,
                    base_risk: 15,
                    description: "File deletion".into(),
                }
            ],
            flag_behaviors: HashMap::from([
                ("-rf".to_string(), vec![BehaviorAction {
                    category: BehaviorCategory::Filesystem,
                    action_type: ActionType::Delete,
                    base_risk: 40,
                    description: "Recursive forced deletion".into(),
                }]),
                ("-r".to_string(), vec![BehaviorAction {
                    category: BehaviorCategory::Filesystem,
                    action_type: ActionType::Delete,
                    base_risk: 30,
                    description: "Recursive deletion".into(),
                }]),
                ("-f".to_string(), vec![BehaviorAction {
                    category: BehaviorCategory::Filesystem,
                    action_type: ActionType::Delete,
                    base_risk: 25,
                    description: "Forced deletion".into(),
                }]),
            ]),
        });

        commands.insert("dd".to_string(), CommandBehavior {
            command: "dd".to_string(),
            default_behaviors: vec![
                BehaviorAction {
                    category: BehaviorCategory::Filesystem,
                    action_type: ActionType::Write,
                    base_risk: 35,
                    description: "Low-level data copy".into(),
                }
            ],
            flag_behaviors: HashMap::new(),
        });

        commands.insert("ln".to_string(), CommandBehavior {
            command: "ln".to_string(),
            default_behaviors: vec![],
            flag_behaviors: HashMap::from([
                ("-s".to_string(), vec![BehaviorAction {
                    category: BehaviorCategory::Filesystem,
                    action_type: ActionType::CreateSymlink,
                    base_risk: 15,
                    description: "Symbolic link creation".into(),
                }]),
            ]),
        });

        commands.insert("mount".to_string(), CommandBehavior {
            command: "mount".to_string(),
            default_behaviors: vec![
                BehaviorAction {
                    category: BehaviorCategory::Filesystem,
                    action_type: ActionType::MountFilesystem,
                    base_risk: 50,
                    description: "Filesystem mount".into(),
                }
            ],
            flag_behaviors: HashMap::new(),
        });
    }

    fn add_system_commands(commands: &mut HashMap<String, CommandBehavior>) {
        commands.insert("systemctl".to_string(), CommandBehavior {
            command: "systemctl".to_string(),
            default_behaviors: vec![
                BehaviorAction {
                    category: BehaviorCategory::SystemModification,
                    action_type: ActionType::ServiceControl,
                    base_risk: 40,
                    description: "Systemd service control".into(),
                }
            ],
            flag_behaviors: HashMap::new(),
        });

        commands.insert("service".to_string(), CommandBehavior {
            command: "service".to_string(),
            default_behaviors: vec![
                BehaviorAction {
                    category: BehaviorCategory::SystemModification,
                    action_type: ActionType::ServiceControl,
                    base_risk: 40,
                    description: "Service control".into(),
                }
            ],
            flag_behaviors: HashMap::new(),
        });

        commands.insert("crontab".to_string(), CommandBehavior {
            command: "crontab".to_string(),
            default_behaviors: vec![
                BehaviorAction {
                    category: BehaviorCategory::SystemModification,
                    action_type: ActionType::CronJob,
                    base_risk: 60,
                    description: "Cron job manipulation".into(),
                }
            ],
            flag_behaviors: HashMap::new(),
        });

        commands.insert("insmod".to_string(), CommandBehavior {
            command: "insmod".to_string(),
            default_behaviors: vec![
                BehaviorAction {
                    category: BehaviorCategory::KernelOperations,
                    action_type: ActionType::DynamicLoad,
                    base_risk: 80,
                    description: "Kernel module loading".into(),
                }
            ],
            flag_behaviors: HashMap::new(),
        });

        commands.insert("modprobe".to_string(), CommandBehavior {
            command: "modprobe".to_string(),
            default_behaviors: vec![
                BehaviorAction {
                    category: BehaviorCategory::KernelOperations,
                    action_type: ActionType::DynamicLoad,
                    base_risk: 70,
                    description: "Kernel module loading".into(),
                }
            ],
            flag_behaviors: HashMap::new(),
        });
    }

    pub fn get_behavior(&self, command: &str) -> Option<&CommandBehavior> {
        self.commands.get(command)
    }
}

impl Default for CommandDatabase {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// SHELL PARSER
// ============================================================================

pub struct ShellParser;

impl ShellParser {
    pub fn new() -> Self {
        Self
    }

    /// Parse content and extract commands with context
    pub fn parse_content(&self, content: &str, function_name: Option<&str>, function_type: FunctionType) -> Vec<ParsedCommand> {
        let mut commands = Vec::new();
        let lines: Vec<&str> = content.lines().collect();

        for (line_idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Skip empty lines
            if trimmed.is_empty() {
                continue;
            }

            // Build context for this line
            let context = self.build_context(&lines, line_idx, function_name, function_type);

            // Skip if entirely in comment
            if context.is_in_comment {
                continue;
            }

            // Parse commands from line
            let line_commands = self.parse_line(trimmed, &context);
            commands.extend(line_commands);
        }

        commands
    }

    fn build_context(&self, lines: &[&str], current_line: usize, function_name: Option<&str>, function_type: FunctionType) -> CommandContext {
        let line = lines[current_line];
        let trimmed = line.trim();

        // Check if line is a comment
        let is_in_comment = trimmed.starts_with('#');

        // Detect conditionals (look back)
        let is_in_conditional = lines[..=current_line].iter().rev()
            .take(10)
            .any(|l| {
                let t = l.trim();
                t.starts_with("if ") || t.starts_with("elif ") ||
                t.starts_with("case ") || t.contains(" && ") || t.contains(" || ")
            });

        // Detect loops
        let is_in_loop = lines[..=current_line].iter().rev()
            .take(10)
            .any(|l| {
                let t = l.trim();
                t.starts_with("for ") || t.starts_with("while ") ||
                t.starts_with("until ")
            });

        // Check for subshell
        let is_in_subshell = line.contains("$(") || line.contains('`');

        // Check if inside string (simplified)
        let is_in_string = self.is_inside_string(trimmed);

        CommandContext {
            function_name: function_name.map(|s| s.to_string()),
            function_type,
            is_in_conditional,
            is_in_loop,
            is_in_subshell,
            is_in_comment,
            is_in_string,
            line_number: current_line + 1,
        }
    }

    fn is_inside_string(&self, line: &str) -> bool {
        // Count unescaped quotes
        let mut in_single = false;
        let mut in_double = false;
        let mut escaped = false;

        for ch in line.chars() {
            if escaped {
                escaped = false;
                continue;
            }

            if ch == '\\' {
                escaped = true;
                continue;
            }

            if ch == '\'' && !in_double {
                in_single = !in_single;
            } else if ch == '"' && !in_single {
                in_double = !in_double;
            }
        }

        // If we end with unclosed quotes, we're inside a string
        in_single || in_double
    }

    fn parse_line(&self, line: &str, context: &CommandContext) -> Vec<ParsedCommand> {
        let mut commands = Vec::new();

        // Remove inline comment (but be careful about # inside strings)
        let effective_line = self.remove_inline_comment(line);

        // Split by pipes (simple split, not handling quotes perfectly)
        let segments = self.split_by_pipes(&effective_line);

        for segment in segments {
            if let Some(cmd) = self.parse_command_segment(&segment, context) {
                commands.push(cmd);
            }
        }

        commands
    }

    fn remove_inline_comment(&self, line: &str) -> String {
        let mut result = String::new();
        let mut in_single_quote = false;
        let mut in_double_quote = false;
        let mut escaped = false;

        for ch in line.chars() {
            if escaped {
                result.push(ch);
                escaped = false;
                continue;
            }

            if ch == '\\' && !in_single_quote {
                escaped = true;
                result.push(ch);
                continue;
            }

            if ch == '\'' && !in_double_quote {
                in_single_quote = !in_single_quote;
                result.push(ch);
                continue;
            }

            if ch == '"' && !in_single_quote {
                in_double_quote = !in_double_quote;
                result.push(ch);
                continue;
            }

            if ch == '#' && !in_single_quote && !in_double_quote {
                break; // Rest is comment
            }

            result.push(ch);
        }

        result
    }

    fn split_by_pipes(&self, line: &str) -> Vec<String> {
        let mut segments = Vec::new();
        let mut current = String::new();
        let mut in_single_quote = false;
        let mut in_double_quote = false;
        let mut escaped = false;
        let mut paren_depth = 0;

        let chars: Vec<char> = line.chars().collect();
        let mut i = 0;

        while i < chars.len() {
            let ch = chars[i];

            if escaped {
                current.push(ch);
                escaped = false;
                i += 1;
                continue;
            }

            if ch == '\\' {
                escaped = true;
                current.push(ch);
                i += 1;
                continue;
            }

            if ch == '\'' && !in_double_quote {
                in_single_quote = !in_single_quote;
                current.push(ch);
                i += 1;
                continue;
            }

            if ch == '"' && !in_single_quote {
                in_double_quote = !in_double_quote;
                current.push(ch);
                i += 1;
                continue;
            }

            if ch == '(' && !in_single_quote && !in_double_quote {
                paren_depth += 1;
            }

            if ch == ')' && !in_single_quote && !in_double_quote && paren_depth > 0 {
                paren_depth -= 1;
            }

            // Check for pipe
            if ch == '|' && !in_single_quote && !in_double_quote && paren_depth == 0 {
                // Check for || (logical OR)
                if i + 1 < chars.len() && chars[i + 1] == '|' {
                    current.push(ch);
                    current.push('|');
                    i += 2;
                    continue;
                }

                // It's a pipe - finish current segment
                let trimmed = current.trim().to_string();
                if !trimmed.is_empty() {
                    segments.push(trimmed);
                }
                current.clear();
                i += 1;
                continue;
            }

            // Check for ; and && (command separators)
            if (ch == ';' || (ch == '&' && i + 1 < chars.len() && chars[i + 1] == '&'))
                && !in_single_quote && !in_double_quote && paren_depth == 0 {
                let trimmed = current.trim().to_string();
                if !trimmed.is_empty() {
                    segments.push(trimmed);
                }
                current.clear();
                if ch == '&' {
                    i += 2; // Skip &&
                } else {
                    i += 1;
                }
                continue;
            }

            current.push(ch);
            i += 1;
        }

        let trimmed = current.trim().to_string();
        if !trimmed.is_empty() {
            segments.push(trimmed);
        }

        segments
    }

    fn parse_command_segment(&self, segment: &str, context: &CommandContext) -> Option<ParsedCommand> {
        let trimmed = segment.trim();
        if trimmed.is_empty() {
            return None;
        }

        // Skip variable assignments without commands
        if trimmed.contains('=') && !trimmed.contains(' ') {
            return None;
        }

        // Extract command name and arguments
        let parts = self.tokenize(trimmed);
        if parts.is_empty() {
            return None;
        }

        let command_name = parts[0].clone();
        let arguments: Vec<CommandArgument> = parts[1..]
            .iter()
            .map(|arg| self.classify_argument(arg))
            .collect();

        Some(ParsedCommand {
            raw_text: segment.to_string(),
            command_name,
            arguments,
            behaviors: Vec::new(),
            context: context.clone(),
        })
    }

    fn tokenize(&self, line: &str) -> Vec<String> {
        let mut tokens = Vec::new();
        let mut current = String::new();
        let mut in_single_quote = false;
        let mut in_double_quote = false;
        let mut escaped = false;

        for ch in line.chars() {
            if escaped {
                current.push(ch);
                escaped = false;
                continue;
            }

            if ch == '\\' {
                escaped = true;
                current.push(ch);
                continue;
            }

            if ch == '\'' && !in_double_quote {
                in_single_quote = !in_single_quote;
                current.push(ch);
                continue;
            }

            if ch == '"' && !in_single_quote {
                in_double_quote = !in_double_quote;
                current.push(ch);
                continue;
            }

            if (ch == ' ' || ch == '\t') && !in_single_quote && !in_double_quote {
                if !current.is_empty() {
                    tokens.push(current.clone());
                    current.clear();
                }
                continue;
            }

            current.push(ch);
        }

        if !current.is_empty() {
            tokens.push(current);
        }

        tokens
    }

    fn classify_argument(&self, arg: &str) -> CommandArgument {
        let arg_type = if arg.starts_with('-') {
            ArgumentType::Flag
        } else if arg.starts_with("http://") || arg.starts_with("https://") ||
                  arg.starts_with("ftp://") || arg.starts_with("git://") {
            ArgumentType::Url
        } else if arg.starts_with('$') || arg.contains("${") {
            ArgumentType::Variable
        } else if arg.starts_with('/') || arg.starts_with("./") || arg.starts_with("../") {
            ArgumentType::Path
        } else if arg.starts_with("$(") || arg.starts_with('`') {
            ArgumentType::Command
        } else {
            ArgumentType::Literal
        };

        let is_user_controlled = arg.contains("$1") || arg.contains("$@") ||
                                  arg.contains("$*") || arg.contains("${1");

        CommandArgument {
            value: arg.to_string(),
            arg_type,
            is_user_controlled,
        }
    }
}

impl Default for ShellParser {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// FINDING
// ============================================================================

#[derive(Debug, Clone)]
pub struct Finding {
    pub command: ParsedCommand,
    pub score: RiskScore,
}

impl Finding {
    /// Convert heuristic finding to legacy SecurityIssue format
    pub fn to_security_issue(&self, thresholds: &RiskThresholds) -> SecurityIssue {
        let level = self.score.to_security_level(thresholds);

        // Generate category from primary behavior
        let category = self.command.behaviors.first()
            .map(|b| format!("{:?}", b.category))
            .unwrap_or_else(|| "Unknown".to_string());

        let title = self.generate_title();
        let description = self.generate_description();
        let recommendation = self.generate_recommendation();

        SecurityIssue {
            level,
            category,
            title,
            description,
            recommendation,
            location: self.command.context.function_name.clone()
                .map(|f| format!("{}() function, line {}", f, self.command.context.line_number))
                .or_else(|| Some(format!("line {}", self.command.context.line_number))),
            context: Some(self.command.raw_text.clone()),
        }
    }

    fn generate_title(&self) -> String {
        if self.command.behaviors.is_empty() {
            return format!("Suspicious command: {}", self.command.command_name);
        }

        let actions: Vec<String> = self.command.behaviors.iter()
            .map(|b| format!("{:?}", b.action_type))
            .collect();

        format!("{} detected in '{}'", actions.join(" + "), self.command.command_name)
    }

    fn generate_description(&self) -> String {
        if self.command.behaviors.is_empty() {
            return format!(
                "Command '{}' detected with risk score {}.",
                self.command.command_name,
                self.score.total_score
            );
        }

        let mut desc = format!(
            "Command '{}' exhibits {} behavior(s) with computed risk score {}.",
            self.command.command_name,
            self.command.behaviors.len(),
            self.score.total_score
        );

        // Add behavior descriptions
        for behavior in &self.command.behaviors {
            desc.push_str(&format!(" {}", behavior.description));
        }

        if self.score.combination_score > 0 {
            desc.push_str(&format!(
                " Dangerous pattern detected (+{} risk).",
                self.score.combination_score
            ));
        }

        desc
    }

    fn generate_recommendation(&self) -> String {
        let mut recommendations = Vec::new();

        for behavior in &self.command.behaviors {
            let rec = match behavior.category {
                BehaviorCategory::Network => "Verify network destinations are legitimate and use HTTPS",
                BehaviorCategory::CodeExecution => "Review dynamically executed code for malicious content",
                BehaviorCategory::Privilege => "Ensure privilege escalation is necessary and justified",
                BehaviorCategory::DataObfuscation => "Decode and inspect obfuscated content manually",
                BehaviorCategory::SystemModification => "Review system modifications and their necessity",
                BehaviorCategory::Filesystem => "Verify file operations are safe and necessary",
                BehaviorCategory::KernelOperations => "Carefully review kernel-level operations",
                _ => "Review this command carefully",
            };
            recommendations.push(rec);
        }

        recommendations.dedup();
        if recommendations.is_empty() {
            "Review this command for potential security issues".to_string()
        } else {
            recommendations.join(". ")
        }
    }
}

// ============================================================================
// HEURISTIC ANALYZER
// ============================================================================

pub struct HeuristicAnalyzer {
    command_database: CommandDatabase,
    combination_patterns: Vec<CombinationPattern>,
    shell_parser: ShellParser,
    thresholds: RiskThresholds,
}

impl HeuristicAnalyzer {
    pub fn new() -> Self {
        Self {
            command_database: CommandDatabase::new(),
            combination_patterns: CombinationPattern::dangerous_patterns(),
            shell_parser: ShellParser::new(),
            thresholds: RiskThresholds::default(),
        }
    }

    /// Main analysis entry point
    pub fn analyze_pkgbuild(&self, pkgbuild: &PkgBuild) -> Vec<Finding> {
        let mut findings: Vec<Finding> = Vec::new();
        let mut all_parsed_commands: Vec<ParsedCommand> = Vec::new();

        // 1. Parse all commands from functions with context
        for (func_name, func_body) in &pkgbuild.functions {
            let func_type = FunctionType::from_name(func_name);
            let mut commands = self.shell_parser.parse_content(
                func_body,
                Some(func_name),
                func_type,
            );

            // Classify behaviors for each command
            for cmd in &mut commands {
                self.classify_command_behaviors(cmd);
            }

            all_parsed_commands.extend(commands);
        }

        // 2. Parse global content (outside functions)
        let global_commands = self.shell_parser.parse_content(
            &pkgbuild.content,
            None,
            FunctionType::Global,
        );

        for mut cmd in global_commands {
            self.classify_command_behaviors(&mut cmd);
            all_parsed_commands.push(cmd);
        }

        // 3. Score individual commands
        for cmd in &all_parsed_commands {
            let score = self.score_command(cmd);
            if score.total_score > 0 {
                findings.push(Finding {
                    command: cmd.clone(),
                    score,
                });
            }
        }

        // 4. Detect and score combination patterns
        let combination_findings = self.detect_combinations(&all_parsed_commands);
        findings.extend(combination_findings);

        // 5. Sort by score descending
        findings.sort_by(|a, b| b.score.total_score.cmp(&a.score.total_score));

        findings
    }

    fn classify_command_behaviors(&self, cmd: &mut ParsedCommand) {
        // Look up command in database
        if let Some(cmd_behavior) = self.command_database.get_behavior(&cmd.command_name) {
            // Add default behaviors
            cmd.behaviors.extend(cmd_behavior.default_behaviors.clone());

            // Check flags in arguments
            for arg in &cmd.arguments {
                if arg.arg_type == ArgumentType::Flag {
                    if let Some(flag_behaviors) = cmd_behavior.flag_behaviors.get(&arg.value) {
                        cmd.behaviors.extend(flag_behaviors.clone());
                    }

                    // Check combined flags (e.g., -rf)
                    if arg.value.starts_with('-') && !arg.value.starts_with("--") && arg.value.len() > 2 {
                        // Try to find each character as a flag
                        for ch in arg.value[1..].chars() {
                            let single_flag = format!("-{}", ch);
                            if let Some(flag_behaviors) = cmd_behavior.flag_behaviors.get(&single_flag) {
                                cmd.behaviors.extend(flag_behaviors.clone());
                            }
                        }
                    }
                }
            }
        }

        // Special detection: pipe to interpreter
        if cmd.raw_text.contains("| bash") || cmd.raw_text.contains("| sh") ||
           cmd.raw_text.contains("|bash") || cmd.raw_text.contains("|sh") ||
           cmd.raw_text.contains("| /bin/bash") || cmd.raw_text.contains("| /bin/sh") {
            cmd.behaviors.push(BehaviorAction {
                category: BehaviorCategory::CodeExecution,
                action_type: ActionType::PipeToInterpreter,
                base_risk: 80,
                description: "Piping content directly to shell interpreter".into(),
            });
        }

        // Special detection: setuid in chmod
        if cmd.command_name == "chmod" {
            for arg in &cmd.arguments {
                if arg.arg_type == ArgumentType::Literal {
                    // Check for setuid patterns (4xxx, 2xxx, 6xxx)
                    if let Some(first_char) = arg.value.chars().next() {
                        if matches!(first_char, '4' | '2' | '6') &&
                           arg.value.len() == 4 &&
                           arg.value.chars().all(|c| c.is_ascii_digit()) {
                            cmd.behaviors.push(BehaviorAction {
                                category: BehaviorCategory::Privilege,
                                action_type: ActionType::Setuid,
                                base_risk: 80,
                                description: "Setting setuid/setgid permissions".into(),
                            });
                        }
                    }

                    // Check for u+s, g+s patterns
                    if arg.value.contains("+s") || arg.value.contains("u+s") || arg.value.contains("g+s") {
                        cmd.behaviors.push(BehaviorAction {
                            category: BehaviorCategory::Privilege,
                            action_type: ActionType::Setuid,
                            base_risk: 80,
                            description: "Setting setuid/setgid permissions".into(),
                        });
                    }
                }
            }
        }

        // Special detection: dangerous rm with variables
        if cmd.command_name == "rm" {
            let has_recursive = cmd.arguments.iter().any(|a|
                a.value == "-r" || a.value == "-rf" || a.value == "-fr" ||
                a.value.contains('r') && a.value.starts_with('-'));
            let has_variable = cmd.arguments.iter().any(|a| a.arg_type == ArgumentType::Variable);

            if has_recursive && has_variable {
                cmd.behaviors.push(BehaviorAction {
                    category: BehaviorCategory::Filesystem,
                    action_type: ActionType::Delete,
                    base_risk: 70,
                    description: "Recursive deletion with variable expansion (dangerous)".into(),
                });
            }
        }
    }

    fn score_command(&self, cmd: &ParsedCommand) -> RiskScore {
        // Skip if in comment
        if cmd.context.is_in_comment {
            return RiskScore::zero();
        }

        // Skip if no behaviors detected
        if cmd.behaviors.is_empty() {
            return RiskScore::zero();
        }

        let mut base_score: u32 = 0;

        // Calculate base score from behaviors
        for behavior in &cmd.behaviors {
            let category_base = behavior.category.base_risk();
            let (multiplier, addition) = behavior.action_type.risk_modifier();
            let behavior_score = ((category_base as f32 * multiplier) as u32) + addition as u32;

            base_score += behavior_score;
        }

        // Apply context adjustment
        let context_adjustment = cmd.context.calculate_adjustment();

        // Apply source trust if URL present
        let source_adjustment: i32 = cmd.arguments.iter()
            .filter(|a| a.arg_type == ArgumentType::Url)
            .map(|a| SourceTrustScorer::score_url(&a.value))
            .sum();

        // Calculate confidence
        let confidence = if cmd.context.is_in_string { 0.5 } else { 1.0 };

        // Compute final score (minimum 0)
        let total_score = (base_score as i32 + context_adjustment + source_adjustment)
            .max(0) as u32;

        RiskScore {
            total_score,
            base_score,
            context_score: context_adjustment,
            combination_score: 0,
            source_trust_score: source_adjustment,
            confidence,
        }
    }

    fn detect_combinations(&self, commands: &[ParsedCommand]) -> Vec<Finding> {
        let mut findings = Vec::new();

        for pattern in &self.combination_patterns {
            let matches = self.find_pattern_matches(commands, pattern);

            for matched_cmds in matches {
                if matched_cmds.is_empty() {
                    continue;
                }

                let primary_cmd = matched_cmds[0].clone();
                let combined_base: u32 = matched_cmds.iter()
                    .map(|c| self.score_command(c).base_score)
                    .sum();

                findings.push(Finding {
                    command: primary_cmd,
                    score: RiskScore {
                        total_score: combined_base + pattern.bonus_score,
                        base_score: combined_base,
                        context_score: 0,
                        combination_score: pattern.bonus_score,
                        source_trust_score: 0,
                        confidence: 0.9,
                    },
                });
            }
        }

        findings
    }

    fn find_pattern_matches(&self, commands: &[ParsedCommand], pattern: &CombinationPattern) -> Vec<Vec<ParsedCommand>> {
        let mut all_matches = Vec::new();

        // Find all commands that match each required behavior
        let mut behavior_matches: Vec<Vec<&ParsedCommand>> = Vec::new();

        for (req_category, req_action) in &pattern.required_behaviors {
            let matching: Vec<&ParsedCommand> = commands.iter()
                .filter(|cmd| {
                    cmd.behaviors.iter().any(|b|
                        b.category == *req_category && b.action_type == *req_action
                    )
                })
                .collect();

            if matching.is_empty() {
                return Vec::new(); // Pattern cannot be satisfied
            }

            behavior_matches.push(matching);
        }

        // For sequential patterns, check proximity
        if behavior_matches.len() >= 2 {
            for first_cmd in &behavior_matches[0] {
                for second_cmd in &behavior_matches[1] {
                    let line_diff = if first_cmd.context.line_number > second_cmd.context.line_number {
                        first_cmd.context.line_number - second_cmd.context.line_number
                    } else {
                        second_cmd.context.line_number - first_cmd.context.line_number
                    };

                    if line_diff <= pattern.proximity_lines {
                        all_matches.push(vec![(*first_cmd).clone(), (*second_cmd).clone()]);
                    }
                }
            }
        }

        all_matches
    }

    /// Convert findings to SecurityIssue format for compatibility
    pub fn findings_to_issues(&self, findings: &[Finding]) -> Vec<SecurityIssue> {
        findings.iter()
            .map(|f| f.to_security_issue(&self.thresholds))
            .collect()
    }

    pub fn thresholds(&self) -> &RiskThresholds {
        &self.thresholds
    }
}

impl Default for HeuristicAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_behavior_category_risk() {
        assert_eq!(BehaviorCategory::KernelOperations.base_risk(), 80);
        assert_eq!(BehaviorCategory::CodeExecution.base_risk(), 70);
        assert_eq!(BehaviorCategory::Benign.base_risk(), 0);
    }

    #[test]
    fn test_function_type_from_name() {
        assert_eq!(FunctionType::from_name("build"), FunctionType::Build);
        assert_eq!(FunctionType::from_name("package"), FunctionType::Package);
        assert_eq!(FunctionType::from_name("post_install"), FunctionType::PostInstall);
        assert_eq!(FunctionType::from_name("random"), FunctionType::Unknown);
    }

    #[test]
    fn test_context_adjustment_comment() {
        let context = CommandContext {
            is_in_comment: true,
            ..Default::default()
        };
        assert!(context.calculate_adjustment() < -100);
    }

    #[test]
    fn test_context_adjustment_post_install() {
        let context = CommandContext {
            function_type: FunctionType::PostInstall,
            ..Default::default()
        };
        assert!(context.calculate_adjustment() > 0);
    }

    #[test]
    fn test_shell_parser_split_pipes() {
        let parser = ShellParser::new();
        let segments = parser.split_by_pipes("curl https://example.com | bash");
        assert_eq!(segments.len(), 2);
        assert!(segments[0].contains("curl"));
        assert!(segments[1].contains("bash"));
    }

    #[test]
    fn test_shell_parser_removes_comments() {
        let parser = ShellParser::new();
        let result = parser.remove_inline_comment("echo hello # this is a comment");
        assert_eq!(result.trim(), "echo hello");
    }

    #[test]
    fn test_shell_parser_preserves_hash_in_string() {
        let parser = ShellParser::new();
        let result = parser.remove_inline_comment(r#"echo "hello # world""#);
        assert!(result.contains("# world"));
    }

    #[test]
    fn test_command_database_curl() {
        let db = CommandDatabase::new();
        let curl = db.get_behavior("curl").unwrap();
        assert!(!curl.default_behaviors.is_empty());
        assert!(curl.flag_behaviors.contains_key("-k"));
    }

    #[test]
    fn test_source_trust_scorer() {
        assert!(SourceTrustScorer::score_url("https://github.com/foo/bar") > 0);
        assert!(SourceTrustScorer::score_url("http://example.com") < 0);
        assert!(SourceTrustScorer::score_url("https://bit.ly/abc") < 0);
        assert!(SourceTrustScorer::score_url("https://something.onion") < -100);
    }

    #[test]
    fn test_risk_score_to_level() {
        let thresholds = RiskThresholds::default();

        let safe_score = RiskScore {
            total_score: 30,
            confidence: 1.0,
            ..RiskScore::zero()
        };
        assert_eq!(safe_score.to_security_level(&thresholds), SecurityLevel::Safe);

        let warning_score = RiskScore {
            total_score: 100,
            confidence: 1.0,
            ..RiskScore::zero()
        };
        assert_eq!(warning_score.to_security_level(&thresholds), SecurityLevel::Warning);

        let critical_score = RiskScore {
            total_score: 200,
            confidence: 1.0,
            ..RiskScore::zero()
        };
        assert_eq!(critical_score.to_security_level(&thresholds), SecurityLevel::Critical);
    }
}
