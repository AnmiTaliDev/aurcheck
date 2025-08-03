use crate::aur::{AurPackage, AurClient};
use crate::pkgbuild::PkgBuild;
use crate::security::{SecurityReport, SecurityRules, SecurityIssue, SecurityLevel};
use crate::errors::Result;
use url::Url;

pub struct SecurityAnalyzer {
    rules: SecurityRules,
    aur_client: AurClient,
}

impl SecurityAnalyzer {
    pub fn new(_config_file: Option<&String>) -> Result<Self> {
        let rules = SecurityRules::new()
            .map_err(|e| crate::errors::AurCheckError::Security(e.to_string()))?;
        let aur_client = AurClient::new()?;

        Ok(Self {
            rules,
            aur_client,
        })
    }

    pub async fn analyze(&self, package: &AurPackage, pkgbuild_content: &str) -> Result<SecurityReport> {
        let mut issues = Vec::new();

        let pkgbuild = PkgBuild::parse(pkgbuild_content)?;

        issues.extend(self.check_pkgbuild_content(&pkgbuild).await?);
        issues.extend(self.check_sources(&pkgbuild).await?);
        issues.extend(self.check_build_functions(&pkgbuild)?);
        issues.extend(self.check_package_metadata(package)?);

        Ok(SecurityReport::new(package.name.clone(), issues))
    }

    async fn check_pkgbuild_content(&self, pkgbuild: &PkgBuild) -> Result<Vec<SecurityIssue>> {
        let issues = self.rules.check_content(&pkgbuild.content, "PKGBUILD");
        Ok(issues)
    }

    async fn check_sources(&self, pkgbuild: &PkgBuild) -> Result<Vec<SecurityIssue>> {
        let mut issues = Vec::new();
        let sources = pkgbuild.get_sources();

        for source in &sources {
            if let Ok(url) = Url::parse(source) {
                issues.extend(self.validate_url(&url).await?);
            } else if source.contains("::") {
                let parts: Vec<&str> = source.split("::").collect();
                if parts.len() == 2 {
                    if let Ok(url) = Url::parse(parts[1]) {
                        issues.extend(self.validate_url(&url).await?);
                    }
                }
            }
        }

        issues.extend(self.check_checksum_validation(pkgbuild).await?);

        Ok(issues)
    }

    async fn validate_url(&self, url: &Url) -> Result<Vec<SecurityIssue>> {
        let mut issues = Vec::new();

        if url.scheme() == "http" {
            issues.push(SecurityIssue {
                level: SecurityLevel::Warning,
                category: "Network Security".to_string(),
                title: "Insecure HTTP source".to_string(),
                description: "Source URL uses insecure HTTP instead of HTTPS".to_string(),
                recommendation: "Use HTTPS sources when possible for better security".to_string(),
                location: Some("source array".to_string()),
                context: Some(url.to_string()),
            });
        }

        // Safe host extraction with proper error handling
        if let Some(host) = url.host_str() {
            if self.is_suspicious_domain(host) {
                issues.push(SecurityIssue {
                    level: SecurityLevel::Critical,
                    category: "Network Security".to_string(),
                    title: "Suspicious domain".to_string(),
                    description: "Source URL points to a potentially suspicious domain".to_string(),
                    recommendation: "Verify the domain is legitimate and safe".to_string(),
                    location: Some("source array".to_string()),
                    context: Some(url.to_string()),
                });
            }

            if self.is_url_shortener(host) {
                issues.push(SecurityIssue {
                    level: SecurityLevel::Critical,
                    category: "Network Security".to_string(),
                    title: "URL shortener detected".to_string(),
                    description: "Source URL uses a URL shortener, hiding the real destination".to_string(),
                    recommendation: "Expand the shortened URL and verify the actual destination".to_string(),
                    location: Some("source array".to_string()),
                    context: Some(url.to_string()),
                });
            }

            // Check for dark web domains
            if self.is_dark_web_domain(host) {
                issues.push(SecurityIssue {
                    level: SecurityLevel::Critical,
                    category: "Network Security".to_string(),
                    title: "Dark web domain detected".to_string(),
                    description: "Source URL points to a dark web (.onion/.i2p) domain".to_string(),
                    recommendation: "Investigate why the package needs to access dark web resources".to_string(),
                    location: Some("source array".to_string()),
                    context: Some(url.to_string()),
                });
            }

            // Check for potentially compromised domains
            if self.is_potentially_compromised_domain(host) {
                issues.push(SecurityIssue {
                    level: SecurityLevel::Warning,
                    category: "Network Security".to_string(),
                    title: "Potentially compromised domain".to_string(),
                    description: "Source URL points to a domain that may have been compromised".to_string(),
                    recommendation: "Verify the domain's security status and consider alternative sources".to_string(),
                    location: Some("source array".to_string()),
                    context: Some(url.to_string()),
                });
            }
        } else {
            issues.push(SecurityIssue {
                level: SecurityLevel::Warning,
                category: "Network Security".to_string(),
                title: "Invalid URL host".to_string(),
                description: "Unable to parse hostname from URL".to_string(),
                recommendation: "Verify URL format is correct".to_string(),
                location: Some("source array".to_string()),
                context: Some(url.to_string()),
            });
        }

        // Validate TLS certificate for HTTPS URLs
        if url.scheme() == "https" {
            issues.extend(self.validate_tls_certificate(url).await?);
        }

        Ok(issues)
    }

    fn get_url_shorteners() -> &'static [&'static str] {
        &[
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
            "short.link", "tiny.cc", "rb.gy", "cutt.ly", "is.gd",
            "v.gd", "x.co", "buff.ly", "yourls.org", "short.cm",
            "1url.com", "clickme.net", "2ya.com", "7.ly"
        ]
    }

    fn get_suspicious_domains() -> &'static [&'static str] {
        &[
            // URL shorteners (subset of concern)
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
            "short.link", "tiny.cc", "rb.gy", "cutt.ly",
            // Suspicious file hosting
            "anonfiles.com", "gofile.io", "temp.sh", "file.io",
            "sendspace.com", "zippyshare.com", "mediafire.com",
            // Compromised/malicious domains (examples)
            "pastebin.com", "hastebin.com", "paste.ee",
            // Suspicious TLDs
            ".tk", ".ml", ".ga", ".cf"
        ]
    }

    fn get_dark_web_domains() -> &'static [&'static str] {
        &[".onion", ".i2p", ".bit"]
    }

    fn get_compromised_indicators() -> &'static [&'static str] {
        &[
            "dyndns", "ddns", "no-ip", "myftp", "servegame",
            "hopto", "gotdns", "zapto", "redirectme"
        ]
    }

    fn is_suspicious_domain(&self, domain: &str) -> bool {
        Self::get_suspicious_domains().iter().any(|&d| {
            domain.contains(d) || domain.ends_with(d)
        })
    }

    fn is_url_shortener(&self, domain: &str) -> bool {
        Self::get_url_shorteners().iter().any(|&d| {
            domain == d || domain.ends_with(&format!(".{}", d))
        })
    }

    fn is_dark_web_domain(&self, domain: &str) -> bool {
        Self::get_dark_web_domains().iter().any(|&d| {
            domain.ends_with(d)
        })
    }

    fn is_potentially_compromised_domain(&self, domain: &str) -> bool {
        Self::get_compromised_indicators().iter().any(|&indicator| {
            domain.contains(indicator)
        })
    }

    async fn check_checksum_validation(&self, pkgbuild: &PkgBuild) -> Result<Vec<SecurityIssue>> {
        let mut issues = Vec::new();
        let sources = pkgbuild.get_sources();
        let checksums = pkgbuild.get_checksums();

        if !sources.is_empty() && checksums.is_empty() {
            issues.push(SecurityIssue {
                level: SecurityLevel::Warning,
                category: "Integrity".to_string(),
                title: "Missing checksums".to_string(),
                description: "Package has sources but no checksums for integrity verification".to_string(),
                recommendation: "Add checksums (sha256sums, etc.) to verify source integrity".to_string(),
                location: Some("PKGBUILD".to_string()),
                context: None,
            });
        }

        if checksums.iter().any(|c| c == "SKIP") {
            issues.push(SecurityIssue {
                level: SecurityLevel::Warning,
                category: "Integrity".to_string(),
                title: "Skipped checksum validation".to_string(),
                description: "Some sources have checksum validation skipped".to_string(),
                recommendation: "Provide proper checksums instead of using SKIP".to_string(),
                location: Some("checksums".to_string()),
                context: None,
            });
        }

        Ok(issues)
    }

    fn check_build_functions(&self, pkgbuild: &PkgBuild) -> Result<Vec<SecurityIssue>> {
        let mut issues = Vec::new();

        for (func_name, func_body) in &pkgbuild.functions {
            let func_issues = self.rules.check_content(func_body, &format!("{}() function", func_name));
            issues.extend(func_issues);
        }

        Ok(issues)
    }

    fn check_package_metadata(&self, package: &AurPackage) -> Result<Vec<SecurityIssue>> {
        let mut issues = Vec::new();

        if package.maintainer.is_none() {
            issues.push(SecurityIssue {
                level: SecurityLevel::Warning,
                category: "Maintenance".to_string(),
                title: "Orphaned package".to_string(),
                description: "Package has no maintainer (orphaned)".to_string(),
                recommendation: "Be cautious with orphaned packages as they may not receive security updates".to_string(),
                location: Some("Package metadata".to_string()),
                context: None,
            });
        }

        let age_days = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() - package.last_modified) / (24 * 3600);

        if age_days > 365 {
            issues.push(SecurityIssue {
                level: SecurityLevel::Warning,
                category: "Maintenance".to_string(),
                title: "Outdated package".to_string(),
                description: format!("Package hasn't been updated in {} days", age_days),
                recommendation: "Check if the package is still actively maintained".to_string(),
                location: Some("Package metadata".to_string()),
                context: Some(format!("Last updated: {} days ago", age_days)),
            });
        }

        Ok(issues)
    }

    async fn validate_tls_certificate(&self, url: &Url) -> Result<Vec<SecurityIssue>> {
        let mut issues = Vec::new();
        
        if let Some(host) = url.host_str() {
            // Simple certificate validation by attempting connection
            let test_url = format!("https://{}", host);
            match self.aur_client.test_tls_connection(&test_url).await {
                Ok(false) => {
                    issues.push(SecurityIssue {
                        level: SecurityLevel::Critical,
                        category: "Network Security".to_string(),
                        title: "Invalid TLS certificate".to_string(),
                        description: "HTTPS URL has invalid or expired TLS certificate".to_string(),
                        recommendation: "Verify the certificate is valid and from a trusted CA".to_string(),
                        location: Some("source array".to_string()),
                        context: Some(url.to_string()),
                    });
                }
                Err(_) => {
                    issues.push(SecurityIssue {
                        level: SecurityLevel::Warning,
                        category: "Network Security".to_string(),
                        title: "Unable to verify TLS certificate".to_string(),
                        description: "Could not connect to verify TLS certificate".to_string(),
                        recommendation: "Manually verify the certificate is valid".to_string(),
                        location: Some("source array".to_string()),
                        context: Some(url.to_string()),
                    });
                }
                Ok(true) => {} // Certificate is valid
            }
        }
        
        Ok(issues)
    }
}