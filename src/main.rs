use clap::{Arg, Command};
use colored::*;
use std::process;

mod aur;
mod analyzer;
mod pkgbuild;
mod security;
mod heuristics;
mod output;
mod errors;

use crate::aur::AurClient;
use crate::analyzer::SecurityAnalyzer;
use crate::output::{OutputFormat, Reporter};
use crate::errors::AurCheckError;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = Command::new("aurcheck")
        .version("0.1.0")
        .author("AnmiTaliDev <anmitali198@gmail.com>")
        .about("Security scanner for AUR packages")
        .arg(
            Arg::new("package")
                .help("Package name to check")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Enable verbose output")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("json")
                .long("json")
                .help("Output results in JSON format")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .help("Path to custom configuration file"),
        )
        .get_matches();

    let package_name = matches.get_one::<String>("package")
        .ok_or_else(|| "Package name is required".to_string())?;
    let verbose = matches.get_flag("verbose");
    let json_output = matches.get_flag("json");
    let config_file = matches.get_one::<String>("config");

    let output_format = if json_output {
        OutputFormat::Json
    } else {
        OutputFormat::Colored
    };

    if let Err(e) = run_check(package_name, verbose, output_format, config_file).await {
        eprintln!("{}: {}", "Error".red().bold(), e);
        process::exit(1);
    }
    
    Ok(())
}

async fn run_check(
    package_name: &str,
    verbose: bool,
    output_format: OutputFormat,
    config_file: Option<&String>,
) -> Result<(), AurCheckError> {
    let reporter = Reporter::new(output_format, verbose);
    
    reporter.start_scan(package_name);

    let aur_client = AurClient::new()?;
    let analyzer = SecurityAnalyzer::new(config_file)?;

    let pkg_info = aur_client.get_package_info(package_name).await?;
    let pkgbuild_content = aur_client.download_pkgbuild(package_name).await?;

    let results = analyzer.analyze(&pkg_info, &pkgbuild_content).await?;
    
    reporter.display_results(&results);

    Ok(())
}