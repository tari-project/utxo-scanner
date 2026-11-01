// Copyright 2026 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! The decrypt stage (DESIGN §6): ElGamal viewable-balance decryption of persisted ciphertexts
//! against a memory-mapped value-lookup file.
//!
//! Decryption always runs from the ciphertext stored on the row — never from the indexer — so it
//! survives the indexer's spend-pruning and out-of-range rows can be retried against a wider
//! lookup file without refetching.

use std::{fs::File, ops::RangeInclusive, path::Path, sync::Arc};

use futures::{StreamExt, stream::FuturesUnordered};
use ootle_rs::crypto::SortedPrefixFileLookup;
use tari_crypto::{
    ristretto::{RistrettoPublicKey, RistrettoSecretKey},
    tari_utilities::ByteArray,
};
use tari_ootle_common_types::engine_types::crypto::{ElgamalVerifiableBalance, ValueLookup};
use tari_template_lib_types::{ResourceAddress, UtxoId};
use tokio::sync::Semaphore;
use tracing::{debug, error, info};

use crate::{
    error::{DecryptError, StoreError},
    store::Store,
};

/// Ciphertexts decrypted per blocking task. Amortizes the lookup's per-batch setup without
/// holding a worker permit for too long.
const DECRYPT_CHUNK: usize = 128;

/// Per-UTXO decrypt result, mapped 1:1 onto `decrypt_state`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecryptOutcome {
    /// -> `Decrypted`, `value = v`
    Value(u64),
    /// -> `FailedOutOfRange` (retryable with a wider lookup file)
    OutOfRange,
    /// -> `Failed` (hard: the stored ciphertext is not a valid ElGamal ciphertext)
    Malformed,
}

/// The memory-mapped value-lookup file, opened once at startup and shared across all decrypt
/// workers (`SortedPrefixFileLookup` is `Send + Sync`; one mmap, page-cache backed).
pub struct ValueLookupFile {
    lookup: SortedPrefixFileLookup,
    path: String,
}

impl ValueLookupFile {
    /// Opens and maps the lookup file, failing fast on a missing file or bad magic.
    ///
    /// # Safety-adjacent caveat
    /// The underlying mmap assumes the file is not truncated/modified while mapped.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Arc<Self>, DecryptError> {
        let path_str = path.as_ref().display().to_string();
        let file = File::open(&path).map_err(|source| DecryptError::OpenLookup {
            path: path_str.clone(),
            source,
        })?;
        // SAFETY: the file is opened read-only and kept mapped for the process lifetime.
        let lookup = unsafe { SortedPrefixFileLookup::load(&file) }.map_err(|source| DecryptError::OpenLookup {
            path: path_str.clone(),
            source,
        })?;
        if lookup.is_empty() {
            return Err(DecryptError::EmptyLookup { path: path_str });
        }
        Ok(Arc::new(Self { lookup, path: path_str }))
    }

    /// The inclusive range of values the file can resolve.
    pub fn range(&self) -> RangeInclusive<u64> {
        self.lookup.range()
    }

    pub fn num_records(&self) -> usize {
        self.lookup.len()
    }

    pub fn path(&self) -> &str {
        &self.path
    }
}

/// Decrypts a chunk of stored 64-byte ciphertexts (`encrypted(32) || public_nonce(32)`).
///
/// CPU-bound — callers run this inside `spawn_blocking`. The batch lookup runs only over
/// well-formed ciphertexts; malformed ones resolve immediately.
pub fn decrypt_ciphertexts<L: ValueLookup>(
    view_secret: &RistrettoSecretKey,
    chunk: &[(UtxoId, Vec<u8>)],
    lookup: &L,
) -> Vec<(UtxoId, DecryptOutcome)> {
    let mut outcomes: Vec<Option<DecryptOutcome>> = Vec::with_capacity(chunk.len());
    let mut proofs = Vec::new();
    let mut proof_indexes = Vec::new();

    for (i, (_, ciphertext)) in chunk.iter().enumerate() {
        match parse_ciphertext(ciphertext) {
            Some(proof) => {
                outcomes.push(None);
                proof_indexes.push(i);
                proofs.push(proof);
            },
            None => outcomes.push(Some(DecryptOutcome::Malformed)),
        }
    }

    if !proofs.is_empty() {
        // The mmap lookup is infallible (its error type is unreachable IO), but the trait is
        // fallible — treat an error as out-of-range rather than crashing the worker.
        match ElgamalVerifiableBalance::decrypt_many(view_secret, &proofs, lookup) {
            Ok(results) => {
                let mut results_iter = results.into_iter();
                for index in proof_indexes {
                    outcomes[index] = Some(match results_iter.next().flatten() {
                        Some(v) => DecryptOutcome::Value(v),
                        None => DecryptOutcome::OutOfRange,
                    });
                }
            },
            Err(err) => {
                error!(%err, "value lookup failed for decrypt chunk");
                for index in proof_indexes {
                    outcomes[index] = Some(DecryptOutcome::OutOfRange);
                }
            },
        }
    }

    chunk
        .iter()
        .zip(outcomes)
        .map(|((id, _), outcome)| (*id, outcome.expect("outcome assigned for every index")))
        .collect()
}

fn parse_ciphertext(bytes: &[u8]) -> Option<ElgamalVerifiableBalance> {
    if bytes.len() != 64 {
        return None;
    }
    let encrypted = RistrettoPublicKey::from_canonical_bytes(&bytes[..32]).ok()?;
    let public_nonce = RistrettoPublicKey::from_canonical_bytes(&bytes[32..]).ok()?;
    Some(ElgamalVerifiableBalance {
        encrypted,
        public_nonce,
    })
}

/// The shared decrypt worker pool: a global semaphore capping real decrypt parallelism across
/// all resource tasks, with each chunk running on tokio's blocking pool.
#[derive(Clone)]
pub struct DecryptPool {
    lookup: Arc<ValueLookupFile>,
    permits: Arc<Semaphore>,
    store: Store,
}

impl DecryptPool {
    pub fn new(lookup: Arc<ValueLookupFile>, workers: usize, store: Store) -> Self {
        Self {
            lookup,
            permits: Arc::new(Semaphore::new(workers.max(1))),
            store,
        }
    }

    pub fn lookup(&self) -> &ValueLookupFile {
        &self.lookup
    }

    pub fn available_workers(&self) -> usize {
        self.permits.available_permits()
    }

    /// Decrypts every pending (`Decrypting`, ciphertext-bearing) row of a resource, recording
    /// outcomes as each chunk completes. Returns the number of rows processed.
    pub async fn drain_pending(
        &self,
        resource_address: &ResourceAddress,
        view_secret: &RistrettoSecretKey,
    ) -> Result<u64, StoreError> {
        let coverage_max = *self.lookup.range().end();
        let mut processed = 0u64;

        loop {
            // Page through pending work; rows leave the Decrypting state as outcomes are
            // recorded, so each iteration fetches a fresh page.
            let pending = self
                .store
                .list_pending_decrypt(resource_address, (DECRYPT_CHUNK * 8) as u32)
                .await?;
            if pending.is_empty() {
                break;
            }

            let mut chunks = pending
                .chunks(DECRYPT_CHUNK)
                .map(|chunk| self.decrypt_chunk(chunk.to_vec(), view_secret.clone()))
                .collect::<FuturesUnordered<_>>();

            while let Some(outcomes) = chunks.next().await {
                processed += outcomes.len() as u64;
                self.store
                    .record_decrypt_outcomes(resource_address, &outcomes, coverage_max)
                    .await?;
            }
        }

        if processed > 0 {
            info!(resource = %resource_address, rows = processed, "decrypted pending rows");
        }
        Ok(processed)
    }

    /// Re-enqueues `FailedOutOfRange` rows whose recorded coverage is below the current lookup
    /// file's coverage (i.e. a wider file has since been supplied). Returns the number requeued.
    pub async fn requeue_out_of_range(&self, resource_address: &ResourceAddress) -> Result<u64, StoreError> {
        let requeued = self
            .store
            .requeue_out_of_range(resource_address, *self.lookup.range().end())
            .await?;
        if requeued > 0 {
            info!(
                resource = %resource_address,
                rows = requeued,
                coverage_max = *self.lookup.range().end(),
                "re-enqueued out-of-range rows against wider lookup coverage",
            );
        }
        Ok(requeued)
    }

    async fn decrypt_chunk(
        &self,
        chunk: Vec<(UtxoId, Vec<u8>)>,
        view_secret: RistrettoSecretKey,
    ) -> Vec<(UtxoId, DecryptOutcome)> {
        let _permit = self
            .permits
            .clone()
            .acquire_owned()
            .await
            .expect("decrypt semaphore is never closed");
        let lookup = self.lookup.clone();
        debug!(rows = chunk.len(), "decrypting chunk");
        tokio::task::spawn_blocking(move || decrypt_ciphertexts(&view_secret, &chunk, &lookup.lookup))
            .await
            .expect("decrypt task never panics")
    }
}

#[cfg(test)]
mod tests {
    use ootle_rs::crypto::GenerateValueLookup;
    use tari_crypto::{
        keys::{PublicKey, SecretKey},
        ristretto::RistrettoPublicKey,
    };

    use super::*;

    fn utxo_id(n: u8) -> UtxoId {
        UtxoId::from_array([n; 32])
    }

    /// Builds a valid viewable-balance ciphertext for `value` decryptable by `view_secret`:
    /// pick nonce `r`, set `R = r·G` and `E = value·G + view_secret·R`, so `E - view_secret·R = value·G`.
    fn encrypt(view_secret: &RistrettoSecretKey, value: u64) -> Vec<u8> {
        let r = RistrettoSecretKey::random(&mut rand::rng());
        let public_nonce = RistrettoPublicKey::from_secret_key(&r);
        let value_point = RistrettoPublicKey::from_secret_key(&RistrettoSecretKey::from(value));
        let encrypted = &value_point + &(view_secret * &public_nonce);
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(encrypted.as_bytes());
        out.extend_from_slice(public_nonce.as_bytes());
        out
    }

    #[test]
    fn decrypts_known_value_and_flags_out_of_range_and_malformed() {
        let view_secret = RistrettoSecretKey::random(&mut rand::rng());
        let lookup = GenerateValueLookup::new(0..=100);

        let chunk = vec![
            (utxo_id(1), encrypt(&view_secret, 42)),
            (utxo_id(2), encrypt(&view_secret, 500)), // beyond the lookup range
            (utxo_id(3), vec![0xFFu8; 64]),           // non-canonical point encoding
            (utxo_id(4), vec![1u8; 10]),              // wrong length
        ];

        let out = decrypt_ciphertexts(&view_secret, &chunk, &lookup);
        assert_eq!(out[0], (utxo_id(1), DecryptOutcome::Value(42)));
        assert_eq!(out[1], (utxo_id(2), DecryptOutcome::OutOfRange));
        assert_eq!(out[2], (utxo_id(3), DecryptOutcome::Malformed));
        assert_eq!(out[3], (utxo_id(4), DecryptOutcome::Malformed));
    }

    #[test]
    fn wrong_view_key_never_yields_a_value() {
        let view_secret = RistrettoSecretKey::random(&mut rand::rng());
        let wrong_secret = RistrettoSecretKey::random(&mut rand::rng());
        let lookup = GenerateValueLookup::new(0..=100);

        let chunk = vec![(utxo_id(1), encrypt(&view_secret, 42))];
        let out = decrypt_ciphertexts(&wrong_secret, &chunk, &lookup);
        assert_eq!(out[0], (utxo_id(1), DecryptOutcome::OutOfRange));
    }
}
