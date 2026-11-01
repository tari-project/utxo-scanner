// Copyright 2026 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

mod api;
mod web;

use std::{net::SocketAddr, path::PathBuf, time::Duration};

use anyhow::Context;
use axum::{Router, routing::get};
use clap::{Parser, Subcommand};
use ootle_rs::{
    Network,
    provider::{IndexerProvider, ProviderBuilder},
    wallet::NoWallet,
};
use tari_template_lib_types::ResourceAddress;
use tracing::info;
use tracing_subscriber::EnvFilter;
use utxo_monitor_core::{
    decrypt::{DecryptPool, ValueLookupFile},
    keys::ViewKeyPair,
    monitor::{Monitor, MonitorConfig},
    store::Store,
};

#[derive(Debug, Parser)]
#[command(
    name = "ootle-utxo-monitor",
    version,
    about = "Monitors the stealth UTXOs of an Ootle resource"
)]
struct Cli {
    /// Indexer to stream UTXO updates from (required for `run` and `resource add`)
    #[arg(long, env = "MONITOR_INDEXER_URL")]
    indexer_url: Option<String>,
    /// Ootle network (localnet, esmeralda, mainnet, ...; required for `run` and `resource add`)
    #[arg(long, env = "MONITOR_NETWORK")]
    network: Option<Network>,
    #[arg(long, env = "MONITOR_DATABASE", default_value = "./ootle-utxo-monitor.db")]
    database: PathBuf,
    /// mmap value-lookup file for ElGamal decryption (required for `run` and `resource add`)
    #[arg(long, env = "MONITOR_VALUE_LOOKUP_FILE")]
    value_lookup_file: Option<PathBuf>,
    /// Address the UI + REST API bind to
    #[arg(long, env = "MONITOR_BIND", default_value = "127.0.0.1:9000")]
    bind: SocketAddr,
    /// Seconds between stream passes once caught up
    #[arg(long, default_value_t = 30)]
    poll_interval: u64,
    #[arg(long, default_value_t = 100)]
    per_shard_limit: u32,
    /// Number of concurrent decrypt workers (default: physical cores, capped at 8)
    #[arg(long)]
    decrypt_workers: Option<usize>,
    /// Genesis backfill floor (epoch) for newly added resources
    #[arg(long, default_value_t = 0)]
    from_epoch: u64,
    #[arg(long, env = "MONITOR_LOG_LEVEL", default_value = "info")]
    log_level: String,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the monitor: ingestion tasks + UI + REST API (default)
    Run,
    /// Manage ElGamal view keys from the CLI
    #[command(subcommand)]
    ViewKey(ViewKeyCmd),
    /// Manage monitored resources from the CLI
    #[command(subcommand)]
    Resource(ResourceCmd),
}

#[derive(Debug, Subcommand)]
enum ViewKeyCmd {
    /// Generate (or import with --secret-hex) a view key
    Add {
        #[arg(long)]
        label: String,
        /// 32-byte Ristretto scalar in hex; generates a fresh key when omitted
        #[arg(long)]
        secret_hex: Option<String>,
    },
    List,
}

#[derive(Debug, Subcommand)]
enum ResourceCmd {
    /// Validate and register a stealth resource for monitoring
    Add {
        address: ResourceAddress,
    },
    List,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().or_else(|_| EnvFilter::try_new(&cli.log_level))?)
        .init();

    let store = Store::open(&cli.database)
        .await
        .with_context(|| format!("failed to open database {}", cli.database.display()))?;

    match cli.command {
        None | Some(Command::Run) => run(cli, store).await,
        Some(Command::ViewKey(ref cmd)) => view_key_cmd(cmd, store).await,
        Some(Command::Resource(ref cmd)) => resource_cmd(cmd, &cli, store).await,
    }
}

async fn connect(cli: &Cli) -> anyhow::Result<IndexerProvider<NoWallet>> {
    let network = cli.network.context("missing --network (or MONITOR_NETWORK)")?;
    let indexer_url = cli
        .indexer_url
        .as_deref()
        .context("missing --indexer-url (or MONITOR_INDEXER_URL)")?;
    ProviderBuilder::new()
        .with_network(network)
        .connect(indexer_url)
        .await
        .with_context(|| format!("failed to connect to indexer at {indexer_url}"))
}

fn default_decrypt_workers() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .min(8)
}

async fn build_monitor(cli: &Cli, store: Store) -> anyhow::Result<Monitor> {
    let value_lookup_file = cli
        .value_lookup_file
        .as_ref()
        .context("missing --value-lookup-file (or MONITOR_VALUE_LOOKUP_FILE)")?;
    let network = cli.network.context("missing --network (or MONITOR_NETWORK)")?;
    let indexer_url = cli
        .indexer_url
        .as_deref()
        .context("missing --indexer-url (or MONITOR_INDEXER_URL)")?;

    let lookup = ValueLookupFile::open(value_lookup_file)
        .with_context(|| format!("failed to open value-lookup file {}", value_lookup_file.display()))?;
    info!(
        path = lookup.path(),
        min = *lookup.range().start(),
        max = *lookup.range().end(),
        records = lookup.num_records(),
        "loaded value-lookup file",
    );

    let provider = connect(cli).await?;
    let epoch = provider
        .get_epoch()
        .await
        .context("indexer is unreachable; check --indexer-url")?;
    let num_preshards = provider
        .get_num_preshards()
        .await
        .context("failed to read the network's shard count from the indexer")?;
    info!(%network, %epoch, ?num_preshards, indexer = %indexer_url, "connected to indexer");

    let workers = cli.decrypt_workers.unwrap_or_else(default_decrypt_workers);
    let decrypt_pool = DecryptPool::new(lookup, workers, store.clone());
    let config = MonitorConfig {
        per_shard_limit: cli.per_shard_limit,
        poll_interval: Duration::from_secs(cli.poll_interval),
        default_from_epoch: cli.from_epoch,
        num_preshards,
    };
    Ok(Monitor::new(store, provider, decrypt_pool, config))
}

async fn run(cli: Cli, store: Store) -> anyhow::Result<()> {
    let monitor = build_monitor(&cli, store).await?;
    let started = monitor.start_all().await?;
    info!(resources = started, "started ingestion tasks for active resources");
    if started == 0 {
        info!("no active resources yet — add one from the web UI or `resource add <address>`");
    }

    let app = Router::new()
        .route("/", get(web::index))
        .route("/{*path}", get(web::asset))
        .nest("/api", api::router(monitor.clone()))
        .layer(tower_http::trace::TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(cli.bind)
        .await
        .with_context(|| format!("failed to bind {}", cli.bind))?;
    info!(bind = %cli.bind, "serving UI + REST API");

    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
        info!("shutting down");
    };
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
        .context("server error")?;

    monitor.shutdown();
    Ok(())
}

async fn view_key_cmd(cmd: &ViewKeyCmd, store: Store) -> anyhow::Result<()> {
    match cmd {
        ViewKeyCmd::Add { label, secret_hex } => {
            let label = label.trim();
            if label.is_empty() {
                anyhow::bail!("--label must not be empty");
            }
            let pair = match secret_hex {
                Some(hex_str) => ViewKeyPair::from_secret_hex(hex_str).context("invalid --secret-hex")?,
                None => ViewKeyPair::generate(),
            };
            let row = store.insert_view_key(label, &pair.secret_bytes(), &pair.public).await?;
            println!("Added view key #{} ({})", row.id, row.label);
            println!("  public: {}", hex::encode(row.public.as_bytes()));
            Ok(())
        },
        ViewKeyCmd::List => {
            let keys = store.list_view_keys().await?;
            if keys.is_empty() {
                println!("No view keys. Add one with `view-key add --label <label>`.");
                return Ok(());
            }
            for key in keys {
                println!(
                    "#{}  {}  public={}  added={}",
                    key.id,
                    key.label,
                    hex::encode(key.public.as_bytes()),
                    key.created_at.format("%Y-%m-%d %H:%M:%S UTC"),
                );
            }
            Ok(())
        },
    }
}

async fn resource_cmd(cmd: &ResourceCmd, cli: &Cli, store: Store) -> anyhow::Result<()> {
    match cmd {
        ResourceCmd::Add { address } => {
            // Reuse the runtime path so CLI adds run the same 3-gate validation as the API.
            let monitor = build_monitor(cli, store).await?;
            let row = monitor.add_resource(*address).await?;
            // The spawned task is not needed for a one-shot CLI add.
            monitor.shutdown();
            println!("Monitoring {address}");
            println!("  view key id:  #{}", row.view_key_id);
            println!("  divisibility: {}", row.divisibility);
            println!("  from epoch:   {}", row.from_epoch);
            Ok(())
        },
        ResourceCmd::List => {
            let resources = store.list_resources().await?;
            if resources.is_empty() {
                println!("No resources. Add one with `resource add <address>`.");
                return Ok(());
            }
            for resource in resources {
                let counts = store.utxo_counts(&resource.resource_address).await?;
                println!(
                    "{}  view_key=#{}  active={}  utxos={} (unspent={}, spent={}, burnt={}, decrypted={})",
                    resource.resource_address,
                    resource.view_key_id,
                    resource.active,
                    counts.total,
                    counts.unspent,
                    counts.spent,
                    counts.burnt,
                    counts.decrypted,
                );
            }
            Ok(())
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offline_subcommands_parse_without_indexer_or_lookup_flags() {
        let cli = Cli::try_parse_from(["ootle-utxo-monitor", "view-key", "list"]).unwrap();
        assert!(matches!(cli.command, Some(Command::ViewKey(ViewKeyCmd::List))));

        let cli = Cli::try_parse_from(["ootle-utxo-monitor", "view-key", "add", "--label", "primary"]).unwrap();
        assert!(matches!(cli.command, Some(Command::ViewKey(ViewKeyCmd::Add { .. }))));

        let cli = Cli::try_parse_from(["ootle-utxo-monitor", "resource", "list"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Resource(ResourceCmd::List))));
    }
}
