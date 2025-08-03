use reqwest::Client;
use serde::{Deserialize, Serialize};
use crate::errors::{AurCheckError, Result as AurResult};

#[derive(Debug, Deserialize, Serialize)]
pub struct AurPackage {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Version")]
    pub version: String,
    #[serde(rename = "Description")]
    pub description: Option<String>,
    #[serde(rename = "URL")]
    pub url: Option<String>,
    #[serde(rename = "URLPath")]
    pub url_path: String,
    #[serde(rename = "Maintainer")]
    pub maintainer: Option<String>,
    #[serde(rename = "FirstSubmitted")]
    pub first_submitted: u64,
    #[serde(rename = "LastModified")]
    pub last_modified: u64,
}

#[derive(Debug, Deserialize)]
struct AurResponse {
    resultcount: u32,
    results: Vec<AurPackage>,
}

pub struct AurClient {
    client: Client,
    base_url: String,
}

impl AurClient {
    pub fn new() -> AurResult<Self> {
        let client = Client::builder()
            .user_agent("aurcheck/0.1.0")
            .build()
            .map_err(AurCheckError::Http)?;

        Ok(Self {
            client,
            base_url: "https://aur.archlinux.org".to_string(),
        })
    }

    pub async fn get_package_info(&self, package_name: &str) -> AurResult<AurPackage> {
        let url = format!("{}/rpc/?v=5&type=info&arg={}", self.base_url, package_name);
        
        let response = self.client
            .get(&url)
            .send()
            .await
            .map_err(AurCheckError::Http)?;

        let aur_response: AurResponse = response
            .json()
            .await
            .map_err(AurCheckError::Http)?;

        if aur_response.resultcount == 0 {
            return Err(AurCheckError::PackageNotFound(package_name.to_string()));
        }

        aur_response.results.into_iter().next()
            .ok_or_else(|| AurCheckError::PackageNotFound(package_name.to_string()))
    }

    pub async fn download_pkgbuild(&self, package_name: &str) -> AurResult<String> {
        let url = format!("{}/cgit/aur.git/plain/PKGBUILD?h={}", self.base_url, package_name);
        
        let response = self.client
            .get(&url)
            .send()
            .await
            .map_err(AurCheckError::Http)?;

        if !response.status().is_success() {
            return Err(AurCheckError::PackageNotFound(package_name.to_string()));
        }

        let content = response
            .text()
            .await
            .map_err(AurCheckError::Http)?;

        Ok(content)
    }


    pub async fn test_tls_connection(&self, url: &str) -> AurResult<bool> {
        match self.client.head(url).send().await {
            Ok(response) => Ok(response.status().is_success() || response.status().is_redirection()),
            Err(e) => {
                // Check if error is TLS-related
                if e.to_string().contains("certificate") || 
                   e.to_string().contains("tls") ||
                   e.to_string().contains("ssl") {
                    Ok(false)
                } else {
                    Err(AurCheckError::Http(e))
                }
            }
        }
    }
}