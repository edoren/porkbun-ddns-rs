use anyhow::{anyhow, Result};
use clap::Parser;
use log::{error, info};
use reqwest;
use serde::{Deserialize, Serialize};
use serde_json::{self, json};
use std::{
    fs,
    path::{Path, PathBuf},
    thread,
    time::Duration,
};
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::{
    filter::LevelFilter, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer,
};

static PORKBUN_API_URL: &str = "https://porkbun.com/api/json/v3";

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// The domain to update
    #[arg(required = true)]
    domain: String,

    /// The subdomains to update
    #[arg(long, num_args=1.., required=true, value_delimiter=',')]
    subdomains: Vec<String>,

    /// The secrets.json file path
    #[arg(long, required = true)]
    secrets: String,

    /// Update time in seconds
    #[arg(short, long, default_value_t = 60)]
    time_update: u64,
}

#[derive(Serialize, Deserialize, Debug)]
struct AppConfig {
    api_key: String,
    secret_key: String,
    domain: String,
    subdomains: Vec<String>,
}

#[derive(Deserialize, Debug)]
struct Secrets {
    api_key: String,
    secret_key: String,
}

#[derive(Deserialize, Clone, Debug)]
struct DNSRecord {
    id: String,
    name: String,
    r#type: String,
    content: String,
    ttl: String,
}

#[derive(Deserialize, Debug)]
struct RetrieveRecordsResponse {
    status: String,
    records: Option<Vec<DNSRecord>>,
}

#[derive(Deserialize, Debug)]
struct StatusResponse {
    status: String,
}

async fn get_records(app_config: &AppConfig) -> Result<Vec<DNSRecord>> {
    let record_domain = &app_config.domain;
    let body = json!({
        "apikey": &app_config.api_key,
        "secretapikey": &app_config.secret_key
    });

    let client = reqwest::Client::new();
    let result = client
        .post(format!("{PORKBUN_API_URL}/dns/retrieve/{record_domain}"))
        .body(body.to_string())
        .send()
        .await?;

    let subdomain_suffix = format!(".{}", app_config.domain);
    let response = result.json::<RetrieveRecordsResponse>().await?;

    if response.status == "SUCCESS" {
        let mut records = response.records.unwrap();
        for record in &mut records {
            let subdomain = match record.name.strip_suffix(&subdomain_suffix) {
                Some(val) => val,
                None => "@",
            };
            record.name = subdomain.into();
        }
        return Ok(records);
    }

    return Err(anyhow!("Failed to retrieve records"));
}

async fn get_records_subdomain(app_config: &AppConfig, r#type: &str) -> Result<Vec<DNSRecord>> {
    let records = get_records(&app_config).await?;
    let new_records = records
        .iter()
        .filter(|record| record.r#type == r#type && record.name != "@")
        .cloned()
        .collect();
    return Ok(new_records);
}

async fn create_record(app_config: &AppConfig, subdomain: &String, content: &String) -> Result<()> {
    let body = json!({
        "apikey": &app_config.api_key,
        "secretapikey": &app_config.secret_key,
        "name": subdomain,
        "type": "A",
        "content": content,
        "ttl": "600"
    });

    let record_domain = &app_config.domain;
    let client = reqwest::Client::new();
    let result = client
        .post(format!("{PORKBUN_API_URL}/dns/create/{record_domain}"))
        .body(body.to_string())
        .send()
        .await?;

    let response = result.json::<StatusResponse>().await?;
    if response.status != "SUCCESS" {
        return Err(anyhow!("API call failed"));
    }

    return Ok(());
}

async fn delete_record(app_config: &AppConfig, record: &DNSRecord) -> Result<()> {
    let body = json!({
        "apikey": &app_config.api_key,
        "secretapikey": &app_config.secret_key
    });

    let record_id = &record.id;
    let record_domain = &app_config.domain;
    let client = reqwest::Client::new();
    let result = client
        .post(format!(
            "{PORKBUN_API_URL}/dns/delete/{record_domain}/{record_id}"
        ))
        .body(body.to_string())
        .send()
        .await?;

    let response = result.json::<StatusResponse>().await?;
    if response.status != "SUCCESS" {
        return Err(anyhow!("API call failed"));
    }

    return Ok(());
}

async fn update_record(app_config: &AppConfig, record: &DNSRecord, content: &String) -> Result<()> {
    let body = json!({
        "apikey": &app_config.api_key,
        "secretapikey": &app_config.secret_key,
        "name": record.name,
        "type": record.r#type,
        "content": content,
        "ttl": record.ttl
    });

    let record_id = &record.id;
    let record_domain = &app_config.domain;
    let client = reqwest::Client::new();
    let result = client
        .post(format!(
            "{PORKBUN_API_URL}/dns/edit/{record_domain}/{record_id}"
        ))
        .body(body.to_string())
        .send()
        .await?;

    let response = result.json::<StatusResponse>().await?;
    if response.status != "SUCCESS" {
        return Err(anyhow!("API call failed"));
    }

    return Ok(());
}

async fn update_dns(app_config: &AppConfig) -> Result<()> {
    let current_ip = public_ip::addr()
        .await
        .ok_or(anyhow!("Couldn't get an IP address"))?
        .to_string();

    let current_subdomain_records = get_records_subdomain(&app_config, "A").await?;

    for subdomain in &app_config.subdomains {
        let mut was_updated = false;
        match current_subdomain_records
            .iter()
            .find(|&r| r.name.eq(subdomain))
        {
            Some(record) => {
                // Update subdomain
                if record.content != current_ip {
                    was_updated = update_record(&app_config, &record, &current_ip)
                        .await
                        .is_ok();
                }
            }
            None => {
                // Create subdomain
                was_updated = create_record(&app_config, &subdomain, &current_ip)
                    .await
                    .is_ok();
            }
        }
        if was_updated {
            info!("Subdomain \"{subdomain}\" updated with IP {current_ip}");
        } else {
            info!("Subdomain \"{subdomain}\" already up to date");
        }
    }

    return Ok(());
}

async fn main_task() -> Result<()> {
    let app_config_dir: PathBuf;
    if Path::new("/.dockerenv").exists() {
        app_config_dir = PathBuf::from("/data");
    } else {
        app_config_dir = dirs::config_dir()
            .expect("Could not find configuration directory")
            .join("porkbun_ddns_rs");
    }

    fs::create_dir_all(&app_config_dir).expect("Error creating configuration directory");

    // Logging

    let logs_dir = app_config_dir.join("logs");
    let default_filter = |filter: LevelFilter| {
        EnvFilter::builder()
            .with_default_directive(filter.into())
            .from_env_lossy()
    };

    let file_appender = RollingFileAppender::builder()
        .max_log_files(7)
        .rotation(Rotation::DAILY)
        .filename_prefix("porkbun_ddns")
        .filename_suffix("log")
        .build(logs_dir.clone())?;
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
    let file_layer = tracing_subscriber::fmt::layer()
        .with_writer(non_blocking)
        .with_ansi(false)
        .with_filter(default_filter(LevelFilter::DEBUG))
        .boxed();

    let stdout_layer = tracing_subscriber::fmt::layer()
        .with_filter(default_filter(LevelFilter::INFO))
        .boxed();

    let mut layers = Vec::new();
    layers.push(file_layer);
    layers.push(stdout_layer);
    tracing_subscriber::registry().with(layers).init();

    // App

    let last_config_path = app_config_dir.join("last_config.json");

    let args = Args::parse();

    let secrets_path = Path::new(&args.secrets);
    let secrets_contents: String =
        fs::read_to_string(&secrets_path).expect("Failed to read secrets file");
    let secrets: Secrets =
        serde_json::from_str(secrets_contents.as_str()).expect("Error parsing configuration file");

    let app_config = AppConfig {
        api_key: secrets.api_key,
        secret_key: secrets.secret_key,
        domain: args.domain,
        subdomains: args.subdomains,
    };

    if last_config_path.exists() {
        let old_app_config_contents =
            fs::read_to_string(&last_config_path).expect("Failed to read old configuration file");
        let old_app_config: AppConfig = serde_json::from_str(old_app_config_contents.as_str())
            .expect("Error parsing configuration file");

        let mut difference = vec![];
        if app_config.domain == old_app_config.domain {
            for subdomain in &old_app_config.subdomains {
                if !app_config.subdomains.contains(&subdomain) {
                    difference.push(subdomain.clone())
                }
            }
        } else {
            difference = old_app_config.subdomains.clone();
        }

        if let Ok(old_records) = get_records_subdomain(&old_app_config, "A").await {
            for record in &old_records {
                if difference.contains(&record.name) {
                    if let Ok(_) = delete_record(&old_app_config, &record).await {
                        info!(
                            "Subdomain \"{}\" removed from domain {}",
                            record.name, old_app_config.domain
                        );
                    };
                }
            }
        }
    }

    let last_config_contents =
        serde_json::to_string_pretty(&app_config).expect("Could not store configuration");
    fs::write(last_config_path, last_config_contents).expect("Could not store configuration");

    loop {
        let res = update_dns(&app_config).await;
        if res.is_err() {
            error!("{:#?}", res);
        }
        thread::sleep(Duration::from_secs(args.time_update));
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let result = main_task().await;
    if let Err(err) = &result {
        error!("Error: {err:?}");
        return result;
    }
    Ok(())
}
