# AURCheck

A comprehensive security scanner for AUR (Arch User Repository) packages written in Rust.

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

## About

AURCheck is a command-line security scanner designed to help Arch Linux users validate the safety of AUR packages before installation. It analyzes PKGBUILD files and associated content to detect potential security vulnerabilities, suspicious commands, and malicious activity.

**Author:** AnmiTaliDev  
**Contact:** anmitali198@gmail.com  
**Repository:** https://github.com/AnmiTaliDev/aurcheck  
**License:** Apache 2.0  

## Features

### 🔍 Security Analysis
- **Suspicious Command Detection:** Identifies potentially dangerous commands like `python -c`, `eval`, and inline shell execution
- **Obfuscation Detection:** Detects base64 encoding/decoding, character translation, and parameter substitution
- **Network Security:** Validates URLs, checks for HTTPS usage, and identifies suspicious domains
- **Privilege Escalation:** Monitors for sudo usage, suspicious file permissions, and ownership changes

### 🌐 URL Validation
- Validates all URLs in PKGBUILD source arrays
- Checks for HTTPS enforcement
- Detects URL shorteners and suspicious domains
- Validates checksum integrity

### 📊 Comprehensive Reporting
- Color-coded security levels (🟢 Safe / 🟡 Warning / 🔴 Critical)
- Detailed vulnerability descriptions
- Actionable security recommendations
- JSON output support for automation

### ⚡ Performance
- Asynchronous operations with Tokio
- Progress indicators for long operations
- Efficient HTTP client with connection pooling

## Installation

### Prerequisites
- Rust 1.70.0 or later
- Internet connection for downloading PKGBUILD files

### From Source
```bash
git clone https://github.com/AnmiTaliDev/aurcheck.git
cd aurcheck
cargo build --release
sudo cp target/release/aurcheck /usr/local/bin/
```

### From AUR (Future)
```bash
yay -S aurcheck
```

## Usage

### Basic Usage
```bash
# Scan a package
aurcheck package-name

# Verbose output with detailed information
aurcheck -v package-name

# JSON output for automation
aurcheck --json package-name
```

### Command Line Options
```
aurcheck [OPTIONS] <PACKAGE>

ARGUMENTS:
    <PACKAGE>    Package name to check

OPTIONS:
    -v, --verbose        Enable verbose output
    -h, --help           Print help information
    -V, --version        Print version information
        --json           Output results in JSON format
    -c, --config <FILE>  Path to custom configuration file
```

### Example Output

#### Safe Package
```
✓ SAFE Package: safe-package

No security issues found.

Summary:
  Total issues: 0

✓ This package appears to be safe to install.
```

#### Package with Issues
```
⚠ WARNING Package: suspicious-package

Security Issues Found:

Critical Issues:
  ✗ Base64 decoding detected
    Location: build() function
    Context: echo "..." | base64 -d
    Description: Package decodes base64 content, which may hide malicious payloads
    Recommendation: Inspect what is being decoded and verify its safety

Warnings:
  ⚠ Insecure HTTP source
    Location: source array
    Context: http://example.com/file.tar.gz
    Description: Source URL uses insecure HTTP instead of HTTPS
    Recommendation: Use HTTPS sources when possible for better security

Summary:
  Total issues: 2
  Critical: 1
  Warnings: 1

⚠ This package has some security concerns. Review the warnings above.
```

## Security Checks

### Suspicious Commands
- `python -c` - Inline Python execution
- `bash -c` - Inline bash execution  
- `eval` - Dynamic code evaluation
- Base64 encoding/decoding operations
- Shell obfuscation techniques

### Network Security
- HTTP vs HTTPS validation
- URL shortener detection
- Suspicious domain identification
- Certificate validation

### Privilege Escalation
- `sudo` usage detection
- Setuid/setgid file permissions
- Root ownership changes
- Unusual privilege operations

### Package Integrity
- Missing checksums validation
- Skipped checksum verification
- Source URL validation
- Package maintenance status

## Configuration

AURCheck supports custom security rules through configuration files:

```bash
aurcheck -c custom-rules.json package-name
```

## JSON Output

For automation and integration with other tools:

```bash
aurcheck --json package-name | jq '.summary.critical_count'
```

Example JSON output:
```json
{
  "package_name": "example-package",
  "overall_level": "Warning",
  "issues": [
    {
      "level": "Warning",
      "category": "Network Security",
      "title": "Insecure HTTP source",
      "description": "Source URL uses insecure HTTP instead of HTTPS",
      "recommendation": "Use HTTPS sources when possible for better security",
      "location": "source array",
      "context": "http://example.com/file.tar.gz"
    }
  ],
  "summary": {
    "total_issues": 1,
    "critical_count": 0,
    "warning_count": 1,
    "safe_count": 0
  }
}
```

## Development

### Building from Source
```bash
git clone https://github.com/AnmiTaliDev/aurcheck.git
cd aurcheck
cargo build
```

### Running Tests
```bash
cargo test
```

### Code Style
```bash
cargo fmt
cargo clippy
```

## Security Considerations

AURCheck is designed as a defensive security tool to help users make informed decisions about AUR packages. It should be used as part of a comprehensive security strategy that includes:

- Regular system updates
- Principle of least privilege
- Code review of PKGBUILD files
- Verification of package maintainer reputation

## Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests.

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Disclaimer

AURCheck is a security analysis tool designed to help identify potential security issues in AUR packages. It should not be considered a complete security solution. Users should always exercise caution when installing packages from the AUR and perform additional security reviews as needed.

The tool is provided "as is" without any warranties. The authors are not responsible for any damage or security issues that may arise from the use of this tool or the packages it analyzes.

## Support

- 📧 Email: anmitali198@gmail.com
- 🐛 Issues: https://github.com/AnmiTaliDev/aurcheck/issues
- 💬 Discussions: https://github.com/AnmiTaliDev/aurcheck/discussions

---

**Made with ❤️ for the Arch Linux community**