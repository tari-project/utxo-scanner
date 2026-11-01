// Copyright 2026 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! The runtime orchestrator. Owns the store, indexer connection, and decrypt pool, and manages
//! one supervised ingestion task per active resource — spawned and cancelled on the fly so
//! resources and view keys can be added while the monitor runs.

use std::{
    collections::HashMap,
    sync::{
        Arc,
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use ootle_rs::{provider::IndexerProvider, wallet::NoWallet};
use tari_crypto::{ristretto::RistrettoSecretKey, tari_utilities::ByteArray};
use tari_ootle_common_types::{Epoch, NumPreshards};
use tari_template_lib_types::{ResourceAddress, crypto::RistrettoPublicKeyBytes};
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::{
    decrypt::{DecryptPool, ValueLookupFile},
    error::StoreError,
    ingest::{Decryptor, IndexerUtxoSource, IngestConfig, ResourceIngestor},
    resource::{ResourceValidationError, find_matching_view_key},
    store::{Store, UtxoCounts},
    types::{ResourceRow, ViewKeyRow},
};

pub type Provider = IndexerProvider<NoWallet>;

#[derive(Debug, thiserror::Error)]
pub enum MonitorError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("indexer error: {0}")]
    Provider(#[from] ootle_rs::provider::ProviderError),
    #[error(transparent)]
    Validation(#[from] ResourceValidationError),
    #[error("view key #{0} not found")]
    ViewKeyNotFound(i64),
    #[error("view key #{id} is still linked by {count} resource(s)")]
    ViewKeyInUse { id: i64, count: usize },
    #[error("stored view key #{0} is corrupt")]
    CorruptViewKey(i64),
}

/// Runtime configuration shared by every spawned ingestion task.
#[derive(Debug, Clone, Copy)]
pub struct MonitorConfig {
    pub per_shard_limit: u32,
    pub poll_interval: Duration,
    pub default_from_epoch: u64,
    /// The network's shard count, used to seed a full-coverage resume cursor. Fetch from the
    /// indexer via [`IndexerProvider::get_num_preshards`](ootle_rs::provider::IndexerProvider::get_num_preshards).
    pub num_preshards: NumPreshards,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            per_shard_limit: 100,
            poll_interval: Duration::from_secs(30),
            default_from_epoch: 0,
            num_preshards: NumPreshards::MAX,
        }
    }
}

#[derive(Clone)]
pub struct Monitor {
    inner: Arc<Inner>,
}

struct Inner {
    store: Store,
    provider: Provider,
    decrypt_pool: DecryptPool,
    config: MonitorConfig,
    /// Task id and cancellation handle per running ingestion task, keyed by resource.
    tasks: Mutex<HashMap<ResourceAddress, (u64, CancellationToken)>>,
    next_task_id: AtomicU64,
    /// Cancelled on shutdown; every task token is a child of this.
    root: CancellationToken,
}

impl Monitor {
    pub fn new(store: Store, provider: Provider, decrypt_pool: DecryptPool, config: MonitorConfig) -> Self {
        Self {
            inner: Arc::new(Inner {
                store,
                provider,
                decrypt_pool,
                config,
                tasks: Mutex::new(HashMap::new()),
                next_task_id: AtomicU64::new(1),
                root: CancellationToken::new(),
            }),
        }
    }

    pub fn store(&self) -> &Store {
        &self.inner.store
    }

    pub fn provider(&self) -> &Provider {
        &self.inner.provider
    }

    pub fn lookup(&self) -> &ValueLookupFile {
        self.inner.decrypt_pool.lookup()
    }

    pub fn available_decrypt_workers(&self) -> usize {
        self.inner.decrypt_pool.available_workers()
    }

    /// True while an ingestion task is running for the resource.
    pub fn is_running(&self, address: &ResourceAddress) -> bool {
        self.inner.tasks.lock().unwrap().contains_key(address)
    }

    // ---------------------------------- view keys ----------------------------------

    pub async fn add_view_key(
        &self,
        label: &str,
        secret: &[u8; 32],
        public: &RistrettoPublicKeyBytes,
    ) -> Result<ViewKeyRow, MonitorError> {
        Ok(self.inner.store.insert_view_key(label, secret, public).await?)
    }

    pub async fn list_view_keys(&self) -> Result<Vec<ViewKeyRow>, MonitorError> {
        Ok(self.inner.store.list_view_keys().await?)
    }

    pub async fn delete_view_key(&self, id: i64) -> Result<(), MonitorError> {
        // Guarded here rather than by a DB constraint so the API can return a clean 409.
        let linked = self
            .inner
            .store
            .list_resources()
            .await?
            .into_iter()
            .filter(|r| r.view_key_id == id)
            .count();
        if linked > 0 {
            return Err(MonitorError::ViewKeyInUse { id, count: linked });
        }
        self.inner.store.delete_view_key(id).await?;
        Ok(())
    }

    // ---------------------------------- resources ----------------------------------

    pub async fn list_resources(&self) -> Result<Vec<ResourceRow>, MonitorError> {
        Ok(self.inner.store.list_resources().await?)
    }

    pub async fn resource_counts(&self, address: &ResourceAddress) -> Result<UtxoCounts, MonitorError> {
        Ok(self.inner.store.utxo_counts(address).await?)
    }

    /// Validates a resource against the stored view keys (3-gate, DESIGN §7), registers it, and
    /// starts its ingestion task. Idempotent: re-adding a running resource is a no-op.
    pub async fn add_resource(&self, address: ResourceAddress) -> Result<ResourceRow, MonitorError> {
        let resource = self.inner.provider.get_resource(address).await?;
        let view_keys = self.inner.store.list_view_keys().await?;
        let view_key = find_matching_view_key(&resource, &view_keys)?;

        self.inner
            .store
            .insert_resource(
                &address,
                view_key.id,
                resource.divisibility(),
                self.inner.config.default_from_epoch,
            )
            .await?;
        let mut row = self.inner.store.get_resource(&address).await?;
        if !row.active {
            self.inner.store.set_resource_active(&address, true).await?;
            row.active = true;
        }
        self.spawn_task(&row).await?;
        Ok(row)
    }

    pub async fn enable_resource(&self, address: &ResourceAddress) -> Result<(), MonitorError> {
        self.inner.store.set_resource_active(address, true).await?;
        let row = self.inner.store.get_resource(address).await?;
        self.spawn_task(&row).await?;
        Ok(())
    }

    /// Cancels the resource's ingestion task and marks it inactive. Its ledger is retained.
    pub async fn disable_resource(&self, address: &ResourceAddress) -> Result<(), MonitorError> {
        self.inner.store.set_resource_active(address, false).await?;
        if let Some((_, token)) = self.inner.tasks.lock().unwrap().remove(address) {
            token.cancel();
        }
        info!(resource = %address, "resource disabled");
        Ok(())
    }

    pub async fn reprocess_failed(&self, address: &ResourceAddress) -> Result<u64, MonitorError> {
        let row = self.inner.store.get_resource(address).await?;
        let requeued = self.inner.decrypt_pool.requeue_out_of_range(address).await?;
        if requeued > 0 {
            let view_key = self.inner.store.get_view_key(row.view_key_id).await?;
            let view_secret = RistrettoSecretKey::from_canonical_bytes(&view_key.secret)
                .map_err(|_| MonitorError::CorruptViewKey(view_key.id))?;
            self.inner.decrypt_pool.drain_pending(address, &view_secret).await?;
        }
        Ok(requeued)
    }

    /// Spawns ingestion tasks for every active resource. Call once on boot.
    pub async fn start_all(&self) -> Result<usize, MonitorError> {
        let resources = self.inner.store.list_active_resources().await?;
        for row in &resources {
            self.spawn_task(row).await?;
        }
        Ok(resources.len())
    }

    /// Cancels all tasks and prevents new ones from being spawned.
    pub fn shutdown(&self) {
        self.inner.root.cancel();
        self.inner.tasks.lock().unwrap().clear();
    }

    async fn spawn_task(&self, row: &ResourceRow) -> Result<(), MonitorError> {
        {
            let tasks = self.inner.tasks.lock().unwrap();
            if tasks.contains_key(&row.resource_address) {
                return Ok(());
            }
        }

        let view_key = self.inner.store.get_view_key(row.view_key_id).await?;
        let view_secret = RistrettoSecretKey::from_canonical_bytes(&view_key.secret)
            .map_err(|_| MonitorError::CorruptViewKey(view_key.id))?;

        let config = IngestConfig {
            from_epoch: Epoch(row.from_epoch),
            per_shard_limit: self.inner.config.per_shard_limit,
            poll_interval: self.inner.config.poll_interval,
            num_preshards: self.inner.config.num_preshards,
        };
        let decryptor = Decryptor {
            pool: self.inner.decrypt_pool.clone(),
            view_secret,
        };
        let ingestor = ResourceIngestor::new(
            IndexerUtxoSource::new(self.inner.provider.clone()),
            self.inner.store.clone(),
            row.resource_address,
            config,
        )
        .with_decryptor(decryptor);

        let token = self.inner.root.child_token();
        let task_id = self.inner.next_task_id.fetch_add(1, Ordering::Relaxed);
        // Insert before spawning so a racing add cannot double-spawn.
        {
            let mut tasks = self.inner.tasks.lock().unwrap();
            if tasks.contains_key(&row.resource_address) {
                return Ok(());
            }
            tasks.insert(row.resource_address, (task_id, token.clone()));
        }

        let inner = self.inner.clone();
        let address = row.resource_address;
        tokio::spawn(async move {
            ingestor.run(token).await;
            // Self-remove when the task ends only if this task is still the active entry,
            // so a disable followed by a fast re-enable does not have the exiting task
            // remove the newly spawned task's token.
            let mut tasks = inner.tasks.lock().unwrap();
            if tasks.get(&address).is_some_and(|(id, _)| *id == task_id) {
                tasks.remove(&address);
            }
        });
        info!(resource = %row.resource_address, "resource ingestion task spawned");
        Ok(())
    }
}
