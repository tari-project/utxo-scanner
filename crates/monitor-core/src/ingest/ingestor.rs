// Copyright 2026 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use std::{pin::pin, time::Duration};

use futures::StreamExt;
use ootle_rs::provider::{ShardCursor, StealthUtxoWatchRequest};
use tari_crypto::ristretto::RistrettoSecretKey;
use tari_ootle_common_types::{Epoch, NumPreshards};
use tari_template_lib_types::ResourceAddress;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::{
    decrypt::DecryptPool,
    error::IngestError,
    ingest::{BatchAssembler, UtxoSource},
    store::{BatchOutcome, Store},
};

/// The decrypt half of a resource task: the shared worker pool plus this resource's view secret.
/// Optional on the ingestor so the ingestion loop stays testable without a lookup file.
#[derive(Clone)]
pub struct Decryptor {
    pub pool: DecryptPool,
    pub view_secret: RistrettoSecretKey,
}

const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy)]
pub struct IngestConfig {
    /// Lower bound epoch for backfill of this resource.
    pub from_epoch: Epoch,
    pub per_shard_limit: u32,
    /// Sleep between passes once every shard is caught up.
    pub poll_interval: Duration,
    /// Shard count used to seed a genesis cursor for a resource with no persisted cursor.
    pub num_preshards: NumPreshards,
}

impl Default for IngestConfig {
    fn default() -> Self {
        Self {
            from_epoch: Epoch(0),
            per_shard_limit: 100,
            poll_interval: Duration::from_secs(30),
            num_preshards: NumPreshards::MAX,
        }
    }
}

/// Aggregate result of one full stream pass over all shards.
#[derive(Debug, Clone, Copy, Default)]
pub struct PassOutcome {
    /// At least one shard reported `per_shard_limit` updates — more data is immediately
    /// available and the next pass should start without sleeping.
    pub has_more: bool,
    /// Shard batches persisted (empty no-advance batches are skipped).
    pub batches_applied: u64,
    /// `Unspent` frames whose outputs were already spent (and pruned) by fetch time; their
    /// `Spent` frames will insert `NoCiphertext` rows on a later pass.
    pub pruned_before_fetch: u64,
    pub changes: BatchOutcome,
}

/// The per-resource ingestion task: repeatedly drains the stealth UTXO update stream from the
/// persisted per-shard cursor, resolving and persisting each shard batch as it completes
/// (stream → fetch → persist, DESIGN §5).
pub struct ResourceIngestor<S> {
    source: S,
    store: Store,
    resource_address: ResourceAddress,
    config: IngestConfig,
    decryptor: Option<Decryptor>,
}

impl<S: UtxoSource> ResourceIngestor<S> {
    pub fn new(source: S, store: Store, resource_address: ResourceAddress, config: IngestConfig) -> Self {
        Self {
            source,
            store,
            resource_address,
            config,
            decryptor: None,
        }
    }

    /// Attaches a decrypt pool + view secret so each pass decrypts the rows it persists.
    pub fn with_decryptor(mut self, decryptor: Decryptor) -> Self {
        self.decryptor = Some(decryptor);
        self
    }

    /// Runs the supervised poll loop until `shutdown` is cancelled. Stream/fetch/store errors are
    /// retried with exponential backoff; the cursor only advances with a fully-persisted batch,
    /// so a failed pass simply re-streams from the last durable position.
    pub async fn run(self, shutdown: CancellationToken) {
        let resource = self.resource_address;
        let mut backoff = INITIAL_BACKOFF;
        info!(%resource, "ingestion task started");

        // A wider lookup file may have been supplied since the last run — retry rows previously
        // beyond coverage before the first pass.
        if let Some(decryptor) = &self.decryptor &&
            let Err(err) = decryptor.pool.requeue_out_of_range(&resource).await
        {
            warn!(%resource, %err, "failed to requeue out-of-range rows at startup");
        }
        self.decrypt_pending().await;

        loop {
            let pass = tokio::select! {
                _ = shutdown.cancelled() => break,
                pass = self.drain_pass() => pass,
            };

            let sleep_for = match pass {
                Ok(outcome) => {
                    backoff = INITIAL_BACKOFF;
                    if outcome.changes.is_empty() {
                        debug!(%resource, "pass complete; no changes");
                    } else {
                        info!(
                            %resource,
                            inserted = outcome.changes.inserted_unspent,
                            replayed = outcome.changes.replayed_unspent,
                            spends = outcome.changes.spends_applied,
                            unknown_spends = outcome.changes.unknown_spends,
                            pruned_before_fetch = outcome.pruned_before_fetch,
                            batches = outcome.batches_applied,
                            "pass complete",
                        );
                    }

                    self.decrypt_pending().await;

                    if outcome.has_more {
                        continue;
                    }
                    self.config.poll_interval
                },
                Err(err) => {
                    warn!(%resource, %err, "ingestion pass failed; retrying in {backoff:?}");
                    let sleep_for = backoff;
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                    sleep_for
                },
            };

            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = tokio::time::sleep(sleep_for) => {},
            }
        }
        info!(%resource, "ingestion task stopped");
    }

    /// Decrypts every pending row of this resource, if a decryptor is attached. Errors are
    /// logged and swallowed — rows stay `Decrypting` and are retried on the next pass.
    async fn decrypt_pending(&self) {
        let Some(decryptor) = &self.decryptor else {
            return;
        };
        if let Err(err) = decryptor
            .pool
            .drain_pending(&self.resource_address, &decryptor.view_secret)
            .await
        {
            warn!(resource = %self.resource_address, %err, "decrypt pass failed");
        }
    }

    /// Drains a single stream pass: every completed shard batch is fetched and persisted
    /// immediately (advancing that shard's cursor); shards are independent.
    pub async fn drain_pass(&self) -> Result<PassOutcome, IngestError> {
        // The request must cover EVERY shard on every pass: the indexer emits nothing for a shard
        // with no updates, so a shard is never recorded in the persisted cursor until it first
        // carries a UTXO. Seeding from genesis (all shards at zero) and overlaying the persisted
        // versions keeps shards we have never seen — where new outputs may land — in the request.
        let mut cursor = ShardCursor::genesis(self.config.num_preshards);
        for (shard, version) in self.store.load_shard_cursor(&self.resource_address).await?.to_pairs() {
            cursor.observe(shard, version);
        }

        let request = StealthUtxoWatchRequest {
            resource_address: self.resource_address,
            from_epoch: self.config.from_epoch,
            shard_state_versions: cursor.to_pairs(),
            // Spent/Burnt frames are required to track spend state.
            unspent_only: false,
            per_shard_limit: self.config.per_shard_limit,
        };

        let mut stream = pin!(self.source.watch(request));
        let mut assembler = BatchAssembler::new();
        let mut pass = PassOutcome::default();

        while let Some(frame) = stream.next().await {
            let Some(batch) = assembler
                .push(frame?)
                .map_err(|err| IngestError::Protocol(err.to_string()))?
            else {
                continue;
            };

            pass.has_more |= batch.num_updates >= self.config.per_shard_limit;

            // An idle shard whose watermark hasn't moved needs no write at all.
            if batch.is_empty() && batch.max_state_version <= cursor.get(batch.shard) {
                continue;
            }

            let new_unspent = if batch.unspent.is_empty() {
                Vec::new()
            } else {
                self.source.fetch_unspent(self.resource_address, &batch.unspent).await?
            };
            pass.pruned_before_fetch += batch.unspent.len().saturating_sub(new_unspent.len()) as u64;

            let outcome = self
                .store
                .apply_shard_batch(&self.resource_address, &batch, &new_unspent)
                .await?;
            cursor.observe(batch.shard, batch.max_state_version);
            pass.batches_applied += 1;
            pass.changes.absorb(outcome);
        }

        if !assembler.is_idle() {
            return Err(IngestError::Protocol("stream ended mid-shard".to_string()));
        }
        Ok(pass)
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, sync::Mutex};

    use futures::Stream;
    use ootle_rs::provider::{StealthUtxoFrame, UtxoWatcherError};
    use tari_ootle_common_types::{StateVersion, shard::Shard};
    use tari_template_lib_types::crypto::{RistrettoPublicKeyBytes, UtxoTag};

    use super::*;
    use crate::{
        test_utils::{new_unspent, nonce, store_with_resource, utxo_id},
        types::{DecryptState, NewUnspentUtxo, SpendState},
    };

    /// Scripted [`UtxoSource`]: each `watch` call pops the next pass's frames; `fetch_unspent`
    /// answers from a fixed `(tag, nonce) -> output` table (a missing pair models an output
    /// pruned between stream and fetch).
    type RequestLog = std::sync::Arc<Mutex<Vec<Vec<(Shard, StateVersion)>>>>;

    struct MockSource {
        passes: Mutex<VecDeque<Vec<Result<StealthUtxoFrame, UtxoWatcherError>>>>,
        fetchable: Vec<((UtxoTag, RistrettoPublicKeyBytes), NewUnspentUtxo)>,
        /// The `shard_state_versions` of each watch request, in call order.
        requests: RequestLog,
    }

    impl MockSource {
        fn new(
            passes: Vec<Vec<Result<StealthUtxoFrame, UtxoWatcherError>>>,
            fetchable: Vec<((UtxoTag, RistrettoPublicKeyBytes), NewUnspentUtxo)>,
        ) -> Self {
            Self {
                passes: Mutex::new(passes.into()),
                fetchable,
                requests: RequestLog::default(),
            }
        }
    }

    impl UtxoSource for MockSource {
        fn watch(
            &self,
            request: StealthUtxoWatchRequest,
        ) -> impl Stream<Item = Result<StealthUtxoFrame, UtxoWatcherError>> + Send {
            self.requests.lock().unwrap().push(request.shard_state_versions);
            let frames = self.passes.lock().unwrap().pop_front().unwrap_or_default();
            futures::stream::iter(frames)
        }

        async fn fetch_unspent(
            &self,
            _resource_address: ResourceAddress,
            pairs: &[(UtxoTag, RistrettoPublicKeyBytes)],
        ) -> Result<Vec<NewUnspentUtxo>, IngestError> {
            Ok(pairs
                .iter()
                .filter_map(|pair| {
                    self.fetchable
                        .iter()
                        .find(|(key, _)| key == pair)
                        .map(|(_, utxo)| utxo.clone())
                })
                .collect())
        }
    }

    fn sos(shard: u32, version: u64, num_updates: u32) -> Result<StealthUtxoFrame, UtxoWatcherError> {
        Ok(StealthUtxoFrame::StartOfShard {
            shard: Shard::from(shard),
            max_state_version: StateVersion::new(version),
            num_updates,
        })
    }

    fn eos(shard: u32, version: u64) -> Result<StealthUtxoFrame, UtxoWatcherError> {
        Ok(StealthUtxoFrame::EndOfShard {
            shard: Shard::from(shard),
            max_state_version: StateVersion::new(version),
        })
    }

    fn unspent_frame(n: u8) -> Result<StealthUtxoFrame, UtxoWatcherError> {
        Ok(StealthUtxoFrame::Unspent {
            tag: UtxoTag::new(n as u32),
            public_nonce: nonce(n),
        })
    }

    fn fetchable(n: u8) -> ((UtxoTag, RistrettoPublicKeyBytes), NewUnspentUtxo) {
        ((UtxoTag::new(n as u32), nonce(n)), new_unspent(n))
    }

    async fn ingestor_with(source: MockSource) -> (ResourceIngestor<MockSource>, Store, ResourceAddress) {
        let (store, address) = store_with_resource().await;
        let config = IngestConfig {
            num_preshards: NumPreshards::P4,
            ..Default::default()
        };
        let ingestor = ResourceIngestor::new(source, store.clone(), address, config);
        (ingestor, store, address)
    }

    #[tokio::test]
    async fn drain_pass_persists_stream_frames_end_to_end() {
        let source = MockSource::new(
            vec![vec![
                sos(1, 10, 2),
                unspent_frame(1),
                unspent_frame(2),
                eos(1, 10),
                sos(2, 20, 1),
                Ok(StealthUtxoFrame::Spent {
                    id: utxo_id(9),
                    version: 1,
                }),
                eos(2, 20),
            ]],
            vec![fetchable(1), fetchable(2)],
        );
        let (ingestor, store, address) = ingestor_with(source).await;

        let pass = ingestor.drain_pass().await.unwrap();
        assert!(!pass.has_more);
        assert_eq!(pass.batches_applied, 2);
        assert_eq!(pass.pruned_before_fetch, 0);
        assert_eq!(pass.changes.inserted_unspent, 2);
        assert_eq!(pass.changes.unknown_spends, 1);

        let row = store.get_utxo(&address, &utxo_id(1)).await.unwrap();
        assert_eq!(row.spend_state, SpendState::Unspent);
        assert_eq!(row.decrypt_state, DecryptState::Decrypting);
        let row = store.get_utxo(&address, &utxo_id(9)).await.unwrap();
        assert_eq!(row.spend_state, SpendState::Spent);
        assert_eq!(row.decrypt_state, DecryptState::NoCiphertext);

        let cursor = store.load_shard_cursor(&address).await.unwrap();
        assert_eq!(cursor.get(Shard::from(1)), StateVersion::new(10));
        assert_eq!(cursor.get(Shard::from(2)), StateVersion::new(20));
    }

    #[tokio::test]
    async fn shard_reporting_the_limit_sets_has_more() {
        let source = MockSource::new(vec![vec![sos(1, 10, 1), unspent_frame(1), eos(1, 10)]], vec![
            fetchable(1),
        ]);
        let (mut ingestor, ..) = ingestor_with(source).await;
        ingestor.config.per_shard_limit = 1;

        let pass = ingestor.drain_pass().await.unwrap();
        assert!(pass.has_more);
    }

    #[tokio::test]
    async fn output_pruned_between_stream_and_fetch_is_counted() {
        let source = MockSource::new(
            vec![vec![sos(1, 10, 2), unspent_frame(1), unspent_frame(2), eos(1, 10)]],
            // Only output 1 is still fetchable; output 2 was spent in-window.
            vec![fetchable(1)],
        );
        let (ingestor, store, address) = ingestor_with(source).await;

        let pass = ingestor.drain_pass().await.unwrap();
        assert_eq!(pass.pruned_before_fetch, 1);
        assert_eq!(pass.changes.inserted_unspent, 1);
        assert!(store.get_utxo(&address, &utxo_id(2)).await.unwrap_err().is_not_found());
    }

    #[tokio::test]
    async fn idle_shards_are_not_written() {
        // The shard reports a watermark equal to the (genesis, zero) cursor with no updates.
        let source = MockSource::new(vec![vec![sos(1, 0, 0), eos(1, 0)]], vec![]);
        let (ingestor, store, address) = ingestor_with(source).await;

        let pass = ingestor.drain_pass().await.unwrap();
        assert_eq!(pass.batches_applied, 0);
        assert!(store.load_shard_cursor(&address).await.unwrap().to_pairs().is_empty());
    }

    #[tokio::test]
    async fn empty_batch_with_new_watermark_still_advances_cursor() {
        let source = MockSource::new(vec![vec![sos(1, 5, 0), eos(1, 5)]], vec![]);
        let (ingestor, store, address) = ingestor_with(source).await;

        let pass = ingestor.drain_pass().await.unwrap();
        assert_eq!(pass.batches_applied, 1);
        let cursor = store.load_shard_cursor(&address).await.unwrap();
        assert_eq!(cursor.get(Shard::from(1)), StateVersion::new(5));
    }

    #[tokio::test]
    async fn truncated_stream_is_a_protocol_error_and_does_not_advance() {
        let source = MockSource::new(vec![vec![sos(1, 10, 1), unspent_frame(1)]], vec![fetchable(1)]);
        let (ingestor, store, address) = ingestor_with(source).await;

        let err = ingestor.drain_pass().await.unwrap_err();
        assert!(matches!(err, IngestError::Protocol(_)));
        assert!(store.load_shard_cursor(&address).await.unwrap().to_pairs().is_empty());
    }

    #[tokio::test]
    async fn stream_error_propagates() {
        let source = MockSource::new(
            vec![vec![Err(UtxoWatcherError::DecodeError("boom".to_string()))]],
            vec![],
        );
        let (ingestor, ..) = ingestor_with(source).await;

        let err = ingestor.drain_pass().await.unwrap_err();
        assert!(matches!(err, IngestError::Watch(_)));
    }

    #[tokio::test]
    async fn every_pass_requests_all_shards_even_after_a_sparse_cursor() {
        // Pass 1 advances only shard 1's cursor; the indexer emits nothing for the other shards,
        // so only shard 1 is persisted. Pass 2 must still request all four shards, or a new
        // output in shard 0/2/3 would never be discovered.
        let source = MockSource::new(vec![vec![sos(1, 10, 1), unspent_frame(1), eos(1, 10)], vec![]], vec![
            fetchable(1),
        ]);
        let request_log = source.requests.clone();
        let (store, address) = store_with_resource().await;
        let config = IngestConfig {
            num_preshards: NumPreshards::P4,
            ..Default::default()
        };
        let ingestor = ResourceIngestor::new(source, store.clone(), address, config);

        ingestor.drain_pass().await.unwrap();
        ingestor.drain_pass().await.unwrap();

        let requests = request_log.lock().unwrap();
        assert_eq!(requests.len(), 2);
        for request in requests.iter() {
            // Shards are 1-indexed (shard 0 is reserved for global substates).
            let shards: Vec<u32> = request.iter().map(|(s, _)| s.as_u32()).collect();
            assert_eq!(shards, vec![1, 2, 3, 4], "every pass must cover all shards");
        }
        // Shard 1 resumes from its watermark; the untouched shards stay at zero.
        assert_eq!(requests[1], vec![
            (Shard::from(1), StateVersion::new(10)),
            (Shard::from(2), StateVersion::zero()),
            (Shard::from(3), StateVersion::zero()),
            (Shard::from(4), StateVersion::zero()),
        ]);
    }
}
