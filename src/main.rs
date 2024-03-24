use clap::Parser;
use reqwest;
use serde::{Deserialize, Serialize};
use serde_json::{self, json};
use std::{error::Error, fs, path::Path, thread, time::Duration};

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
    #[arg(short, long, default_value_t=60)]
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

async fn get_records(app_config: &AppConfig) -> Result<Vec<DNSRecord>, Box<dyn Error>> {
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

    return Err("Failed to retrieve records".into());
}

async fn get_records_subdomain(
    app_config: &AppConfig,
    r#type: &str,
) -> Result<Vec<DNSRecord>, Box<dyn Error>> {
    let records = get_records(&app_config).await?;
    let new_records = records
        .iter()
        .filter(|record| record.r#type == r#type && record.name != "@")
        .cloned()
        .collect();
    return Ok(new_records);
}

async fn create_record(
    app_config: &AppConfig,
    subdomain: &String,
    content: &String,
) -> Result<(), Box<dyn Error>> {
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
        return Err("API call failed".into());
    }

    return Ok(());
}

async fn delete_record(app_config: &AppConfig, record: &DNSRecord) -> Result<(), Box<dyn Error>> {
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
        return Err("API call failed".into());
    }

    return Ok(());
}

async fn update_record(
    app_config: &AppConfig,
    record: &DNSRecord,
    content: &String,
) -> Result<(), Box<dyn Error>> {
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
        return Err("API call failed".into());
    }

    return Ok(());
}

async fn update_dns(app_config: &AppConfig) -> Result<(), Box<dyn Error>> {
    let current_ip = match public_ip::addr().await {
        Some(ip) => ip.to_string(),
        None => {
            return Err("Couldn't get an IP address".into());
        }
    };

    let current_subdomain_records = get_records_subdomain(&app_config, "A").await?;
    if current_subdomain_records.len() == 0 {
        // return Err("Could not retrieve any records with this domain, make sure you own it.".into());
    }

    for subdomain in &app_config.subdomains {
        match current_subdomain_records
            .iter()
            .find(|&r| r.name.eq(subdomain))
        {
            Some(record) => {
                // Update subdomain
                if record.content == current_ip {
                    println!("Subdomain \"{subdomain}\" already up to date");
                    continue;
                }
                update_record(&app_config, &record, &current_ip).await;
                println!("Subdomain \"{subdomain}\" updated with IP {current_ip}");
            }
            None => {
                // Create subdomain
                create_record(&app_config, &subdomain, &current_ip).await;
                println!("Subdomain \"{subdomain}\" updated with IP {current_ip}");
            }
        }
    }

    return Ok(());
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    let config_dir = dirs::config_dir().expect("Could not find configuration directory");

    let config_dir = config_dir.join("porkbun_ddns_rs");
    fs::create_dir_all(&config_dir).expect("Error creating configuration directory");

    let last_config_path = config_dir.join("last_config.json");

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
                        println!(
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
            return res;
        }
        thread::sleep(Duration::from_millis(args.time_update * 1000));
    }
}
