use anyhow::{anyhow, Context, Result};
use clap::Parser;
use log::{debug, error, info};
use reqwest;
use serde::{Deserialize, Serialize};
use serde_json::{self, json};
use std::{
    net::{IpAddr, ToSocketAddrs},
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};
use tokio::{
    fs,
    time::{self, sleep},
};
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::{
    filter::LevelFilter, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer,
};
use url::Url;

static PORKBUN_API_URL: &str = "https://api.porkbun.com/api/json/v3";

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

async fn get_external_ip() -> Result<IpAddr> {
    match public_ip::addr()
        .await
        .context("Could not retrieve the external IP")
    {
        Ok(IpAddr::V4(ip)) => {
            if !ip.is_private() {
                Ok(IpAddr::V4(ip))
            } else {
                Err(anyhow!("IP is private"))
            }
        }
        Ok(IpAddr::V6(ip)) => Ok(IpAddr::V6(ip)),
        Err(err) => Err(err),
    }
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
        .await
        .context("Failed to retrieve DNS records")?;

    let subdomain_suffix = format!(".{}", app_config.domain);
    let response = result
        .json::<RetrieveRecordsResponse>()
        .await
        .context("Could not parse retrieved DNS records")?;

    if response.status == "SUCCESS" {
        let mut records = response.records.context("No records found")?;
        for record in &mut records {
            let subdomain = match record.name.strip_suffix(&subdomain_suffix) {
                Some(val) => val,
                None => "@",
            };
            record.name = subdomain.into();
        }
        return Ok(records);
    }

    return Err(anyhow!("Failed to retrieve DNS records"));
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

async fn create_record(app_config: &AppConfig, subdomain: &str, content: &str) -> Result<()> {
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
        .await
        .context("Failed to create DNS record")?;

    let response = result
        .json::<StatusResponse>()
        .await
        .context("Could not parse DNS create response")?;
    if response.status != "SUCCESS" {
        return Err(anyhow!(
            "Invalid reponse status {} for DNS create endpoint",
            response.status
        ));
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
        .await
        .context("Failed to delete DNS record")?;

    let response = result
        .json::<StatusResponse>()
        .await
        .context("Could not parse DNS delete response")?;
    if response.status != "SUCCESS" {
        return Err(anyhow!(
            "Invalid reponse status {} for DNS delete endpoint",
            response.status
        ));
    }

    return Ok(());
}

async fn update_record(app_config: &AppConfig, record: &DNSRecord, content: &str) -> Result<()> {
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
        .await
        .context("Failed to edit DNS record")?;

    let response = result
        .json::<StatusResponse>()
        .await
        .context("Could not parse DNS edit response")?;
    if response.status != "SUCCESS" {
        return Err(anyhow!(
            "Invalid reponse status {} for DNS edit endpoint",
            response.status
        ));
    }

    return Ok(());
}

async fn update_dns(app_config: &AppConfig, ip: &str) -> Result<Vec<String>> {
    let current_subdomain_records = get_records_subdomain(&app_config, "A").await?;

    let mut updated_subdomains = Vec::new();
    for subdomain in &app_config.subdomains {
        let mut was_updated = false;
        match current_subdomain_records
            .iter()
            .find(|&r| r.name.eq(subdomain))
        {
            Some(record) => {
                // Update subdomain
                if &record.content != ip {
                    was_updated = update_record(&app_config, &record, ip).await.is_ok();
                }
            }
            None => {
                // Create subdomain
                was_updated = create_record(&app_config, &subdomain, ip).await.is_ok();
            }
        }
        if was_updated {
            updated_subdomains.push(subdomain.clone());
        }
    }

    return Ok(updated_subdomains);
}

async fn update_dns_with_current_ip(app_config: &AppConfig) -> Result<(Vec<String>, String)> {
    let current_ip = get_external_ip().await?.to_string();
    update_dns(&app_config, &current_ip)
        .await
        .map(|s| (s, current_ip))
}

async fn main_task(mut connection_status_rx: tokio::sync::watch::Receiver<bool>) -> Result<()> {
    let app_config_dir: PathBuf;
    if Path::new("/.dockerenv").exists() {
        app_config_dir = PathBuf::from("/data");
    } else {
        app_config_dir = dirs::config_dir()
            .context("Could not find configuration directory")?
            .join("porkbun_ddns_rs");
    }

    fs::create_dir_all(&app_config_dir)
        .await
        .map_err(|e| anyhow!("Could not create configuration directory: {e}"))?;

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
    let secrets_contents: String = fs::read_to_string(&secrets_path)
        .await
        .map_err(|e| anyhow!("Failed to read secrets file: {e}"))?;
    let secrets: Secrets = serde_json::from_str(secrets_contents.as_str())
        .map_err(|e| anyhow!("Could not parse configuration file: {e}"))?;

    let app_config = AppConfig {
        api_key: secrets.api_key,
        secret_key: secrets.secret_key,
        domain: args.domain,
        subdomains: args.subdomains,
    };

    if last_config_path.exists() {
        let old_app_config_contents = fs::read_to_string(&last_config_path)
            .await
            .map_err(|e| anyhow!("Failed to read old configuration file: {e}"))?;
        let old_app_config: AppConfig = serde_json::from_str(old_app_config_contents.as_str())
            .map_err(|e| anyhow!("Could not parse old configuration file: {e}"))?;

        let mut difference = vec![];
        if app_config.domain == old_app_config.domain {
            for subdomain in &old_app_config.subdomains {
                if !app_config.subdomains.contains(subdomain) {
                    difference.push(subdomain.clone())
                }
            }
        } else {
            difference = old_app_config.subdomains.clone();
        }

        let mut deleted_subdomains = Vec::new();
        if let Ok(old_records) = get_records_subdomain(&old_app_config, "A").await {
            for record in old_records {
                if difference.contains(&record.name)
                    && delete_record(&old_app_config, &record).await.is_ok()
                {
                    deleted_subdomains.push(record.name);
                }
            }
        }

        if !deleted_subdomains.is_empty() {
            info!(
                "Subdomains ({}) removed from domain {}",
                deleted_subdomains.join(", "),
                old_app_config.domain
            );
        }
    }

    let last_config_contents = serde_json::to_string(&app_config)
        .map_err(|e| anyhow!("Could format configuration: {e}"))?;

    fs::write(last_config_path, last_config_contents)
        .await
        .map_err(|e| anyhow!("Could not store configuration: {e}"))?;

    let mut interval = time::interval(Duration::from_secs(args.time_update));
    let mut was_updated_recently = true;
    loop {
        match update_dns_with_current_ip(&app_config).await {
            Ok((updated_subdomains, current_ip)) => {
                if !updated_subdomains.is_empty() {
                    info!(
                        "Subdomains ({}) updated with IP {current_ip}",
                        updated_subdomains.join(", ")
                    );
                    was_updated_recently = true;
                } else if was_updated_recently {
                    let not_updated_subdomains: Vec<String> = app_config
                        .subdomains
                        .iter()
                        .cloned()
                        .filter(|s| !updated_subdomains.contains(s))
                        .collect();
                    info!(
                        "Subdomains ({}) already up to date",
                        not_updated_subdomains.join(", ")
                    );
                    was_updated_recently = false;
                }
            }
            Err(e) => {
                error!("Failed to update the DNS records, retrying");
                debug!("{e}");
                if *connection_status_rx.borrow() {
                    sleep(Duration::from_secs(1)).await;
                    continue;
                }
            }
        }

        let mut has_connection = *connection_status_rx.borrow();
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if has_connection {
                        break;
                    }
                }
                result = connection_status_rx.changed() => {
                    if result.is_ok() {
                        has_connection = *connection_status_rx.borrow_and_update();
                        if !has_connection {
                            error!("Connection to internet lost, waiting for reconnection");
                            continue;
                        }
                        info!("Connection to internet restablished, updating the DNS records");
                        was_updated_recently = true;
                        interval.reset_immediately();
                        break;
                    }
                }
            }
        }
    }
}

async fn check_connection() -> bool {
    if let Ok(porkurl) = Url::from_str(PORKBUN_API_URL) {
        if let Some(domain) = porkurl.domain() {
            return (domain.to_owned() + ":443").to_socket_addrs().is_ok();
        }
    }
    return false;
}

async fn connection_check_task(connection_status_tx: tokio::sync::watch::Sender<bool>) {
    let mut interval = time::interval(Duration::from_secs(1));

    loop {
        interval.tick().await;
        let has_connection = check_connection().await;
        if has_connection != *connection_status_tx.borrow() {
            let _res = connection_status_tx.send(has_connection);
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let (connection_watch_tx, mut connection_watch_rx) =
        tokio::sync::watch::channel(check_connection().await);

    let has_connection = *connection_watch_rx.borrow_and_update();
    if !has_connection {
        let e = anyhow!("Failed to establish connection to the internet");
        error!("Error: {e}");
        return Err(e);
    }

    let (_, result) = tokio::join!(
        connection_check_task(connection_watch_tx),
        main_task(connection_watch_rx)
    );
    if let Err(e) = &result {
        error!("Error: {e}");
    }

    return result;
}
