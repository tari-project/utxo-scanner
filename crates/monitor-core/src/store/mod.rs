// Copyright 2026 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! sqlite persistence for view keys, monitored resources, UTXO rows, and per-shard resume
//! cursors.
//!
//! All getters return [`StoreError::NotFound`] when the row is absent — use
//! [`Optional::optional`](crate::error::Optional) to convert to `Option`.

#[cfg(test)]
mod tests;

use std::{path::Path, str::FromStr};

use chrono::Utc;
use ootle_rs::provider::ShardCursor;
use sqlx::{
    Row,
    SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteRow},
};
use tari_ootle_common_types::{StateVersion, shard::Shard};
use tari_template_lib_types::{
    ResourceAddress,
    UtxoId,
    crypto::{RistrettoPublicKeyBytes, UtxoTag},
};

use crate::{
    error::StoreError,
    types::{DecryptState, NewUnspentUtxo, ResourceRow, ShardBatch, SpendState, UtxoRow, ViewKeyRow},
};

/// Counts of UTXO rows for a resource, grouped along both state axes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UtxoCounts {
    pub total: u64,
    pub unspent: u64,
    pub spent: u64,
    pub burnt: u64,
    pub decrypting: u64,
    pub decrypted: u64,
    pub failed: u64,
    pub failed_out_of_range: u64,
    pub no_ciphertext: u64,
}

/// Filters and keyset cursor for [`Store::query_utxos`].
#[derive(Debug, Clone)]
pub struct UtxoQuery<'a> {
    pub resource_address: &'a ResourceAddress,
    pub spend_state: Option<SpendState>,
    pub decrypt_state: Option<DecryptState>,
    pub utxo_id: Option<UtxoId>,
    /// Keyset cursor: the `rowid` of the last row of the previous page.
    pub after: Option<i64>,
    pub limit: u32,
}

impl<'a> UtxoQuery<'a> {
    pub fn new(resource_address: &'a ResourceAddress) -> Self {
        Self {
            resource_address,
            spend_state: None,
            decrypt_state: None,
            utxo_id: None,
            after: None,
            limit: 100,
        }
    }
}

/// Result of applying one [`ShardBatch`] in a single transaction.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BatchOutcome {
    /// Unspent outputs inserted for the first time.
    pub inserted_unspent: u64,
    /// Unspent outputs that already existed (stream replay after a crash mid-pass).
    pub replayed_unspent: u64,
    /// Spend/burn events applied to rows we had previously seen unspent.
    pub spends_applied: u64,
    /// Spend/burn events for outputs never seen unspent — inserted as `NoCiphertext` rows.
    pub unknown_spends: u64,
}

impl BatchOutcome {
    pub fn absorb(&mut self, other: BatchOutcome) {
        self.inserted_unspent += other.inserted_unspent;
        self.replayed_unspent += other.replayed_unspent;
        self.spends_applied += other.spends_applied;
        self.unknown_spends += other.unknown_spends;
    }

    pub fn is_empty(&self) -> bool {
        *self == BatchOutcome::default()
    }
}

#[derive(Debug, Clone)]
pub struct Store {
    pool: SqlitePool,
}

impl Store {
    /// Opens (creating if missing) the database at `path` and runs migrations.
    pub async fn open<P: AsRef<Path>>(path: P) -> Result<Self, StoreError> {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(SqliteJournalMode::Wal);
        Self::connect(options).await
    }

    /// An in-memory database for tests.
    pub async fn in_memory() -> Result<Self, StoreError> {
        // A single connection: each in-memory sqlite connection is a distinct database.
        let options = SqliteConnectOptions::new().in_memory(true).foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .min_connections(1)
            .max_connections(1)
            .connect_with(options)
            .await?;
        sqlx::migrate!("./migrations").run(&pool).await?;
        Ok(Self { pool })
    }

    async fn connect(options: SqliteConnectOptions) -> Result<Self, StoreError> {
        let pool = SqlitePoolOptions::new().connect_with(options).await?;
        sqlx::migrate!("./migrations").run(&pool).await?;
        Ok(Self { pool })
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    // ---------------------------------- view keys ----------------------------------

    pub async fn insert_view_key(
        &self,
        label: &str,
        secret: &[u8; 32],
        public: &RistrettoPublicKeyBytes,
    ) -> Result<ViewKeyRow, StoreError> {
        let now = Utc::now();
        let res = sqlx::query("INSERT INTO view_keys (label, secret, public, created_at) VALUES (?, ?, ?, ?)")
            .bind(label)
            .bind(secret.as_slice())
            .bind(public.as_bytes())
            .bind(now)
            .execute(&self.pool)
            .await?;
        Ok(ViewKeyRow {
            id: res.last_insert_rowid(),
            label: label.to_string(),
            secret: *secret,
            public: *public,
            created_at: now,
        })
    }

    pub async fn get_view_key(&self, id: i64) -> Result<ViewKeyRow, StoreError> {
        sqlx::query("SELECT id, label, secret, public, created_at FROM view_keys WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(StoreError::NotFound { entity: "view key" })
            .and_then(|row| decode_view_key(&row))
    }

    pub async fn list_view_keys(&self) -> Result<Vec<ViewKeyRow>, StoreError> {
        sqlx::query("SELECT id, label, secret, public, created_at FROM view_keys ORDER BY id")
            .fetch_all(&self.pool)
            .await?
            .iter()
            .map(decode_view_key)
            .collect()
    }

    pub async fn delete_view_key(&self, id: i64) -> Result<(), StoreError> {
        let res = sqlx::query("DELETE FROM view_keys WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        if res.rows_affected() == 0 {
            return Err(StoreError::NotFound { entity: "view key" });
        }
        Ok(())
    }

    // ---------------------------------- resources ----------------------------------

    /// Registers a resource for monitoring. Idempotent on `resource_address`.
    pub async fn insert_resource(
        &self,
        address: &ResourceAddress,
        view_key_id: i64,
        divisibility: u8,
        from_epoch: u64,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO resources (resource_address, view_key_id, divisibility, from_epoch, active, added_at) VALUES \
             (?, ?, ?, ?, 1, ?) ON CONFLICT (resource_address) DO NOTHING",
        )
        .bind(address.to_string())
        .bind(view_key_id)
        .bind(divisibility as i64)
        .bind(from_epoch as i64)
        .bind(Utc::now())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_resource(&self, address: &ResourceAddress) -> Result<ResourceRow, StoreError> {
        sqlx::query(
            "SELECT resource_address, view_key_id, divisibility, from_epoch, active, added_at FROM resources WHERE \
             resource_address = ?",
        )
        .bind(address.to_string())
        .fetch_optional(&self.pool)
        .await?
        .ok_or(StoreError::NotFound { entity: "resource" })
        .and_then(|row| decode_resource(&row))
    }

    pub async fn list_resources(&self) -> Result<Vec<ResourceRow>, StoreError> {
        sqlx::query(
            "SELECT resource_address, view_key_id, divisibility, from_epoch, active, added_at FROM resources ORDER BY \
             added_at",
        )
        .fetch_all(&self.pool)
        .await?
        .iter()
        .map(decode_resource)
        .collect()
    }

    pub async fn list_active_resources(&self) -> Result<Vec<ResourceRow>, StoreError> {
        Ok(self.list_resources().await?.into_iter().filter(|r| r.active).collect())
    }

    pub async fn set_resource_active(&self, address: &ResourceAddress, active: bool) -> Result<(), StoreError> {
        let res = sqlx::query("UPDATE resources SET active = ? WHERE resource_address = ?")
            .bind(active)
            .bind(address.to_string())
            .execute(&self.pool)
            .await?;
        if res.rows_affected() == 0 {
            return Err(StoreError::NotFound { entity: "resource" });
        }
        Ok(())
    }

    // ---------------------------------- cursors ----------------------------------

    /// Loads the persisted per-shard resume cursor for a resource. Empty if the resource has
    /// never completed a shard batch (callers seed a genesis cursor).
    pub async fn load_shard_cursor(&self, address: &ResourceAddress) -> Result<ShardCursor, StoreError> {
        let rows = sqlx::query("SELECT shard, state_version FROM shard_cursors WHERE resource_address = ?")
            .bind(address.to_string())
            .fetch_all(&self.pool)
            .await?;
        let pairs = rows
            .into_iter()
            .map(|row| {
                let shard: i64 = row.try_get("shard")?;
                let state_version: i64 = row.try_get("state_version")?;
                Ok((Shard::from(shard as u32), StateVersion::new(state_version as u64)))
            })
            .collect::<Result<Vec<_>, sqlx::Error>>()?;
        Ok(ShardCursor::from_pairs(pairs))
    }

    // ---------------------------------- utxos ----------------------------------

    pub async fn get_utxo(&self, address: &ResourceAddress, id: &UtxoId) -> Result<UtxoRow, StoreError> {
        sqlx::query(&format!(
            "SELECT {UTXO_COLUMNS} FROM utxos WHERE resource_address = ? AND utxo_id = ?"
        ))
        .bind(address.to_string())
        .bind(id.as_bytes().as_slice())
        .fetch_optional(&self.pool)
        .await?
        .ok_or(StoreError::NotFound { entity: "utxo" })
        .and_then(|row| decode_utxo(&row))
    }

    pub async fn list_utxos(&self, address: &ResourceAddress) -> Result<Vec<UtxoRow>, StoreError> {
        sqlx::query(&format!(
            "SELECT {UTXO_COLUMNS} FROM utxos WHERE resource_address = ? ORDER BY rowid DESC"
        ))
        .bind(address.to_string())
        .fetch_all(&self.pool)
        .await?
        .iter()
        .map(decode_utxo)
        .collect()
    }

    /// Keyset-paginated UTXO listing in discovery order — most recently scanned first (`rowid`, the
    /// monotonic insertion counter, descending). Pass the last row's `rowid` as `after` to fetch
    /// the next page. Optional exact/state filters narrow the result.
    pub async fn query_utxos(&self, query: &UtxoQuery<'_>) -> Result<Vec<UtxoRow>, StoreError> {
        let mut sql = format!("SELECT {UTXO_COLUMNS} FROM utxos WHERE resource_address = ?");
        if query.spend_state.is_some() {
            sql.push_str(" AND spend_state = ?");
        }
        if query.decrypt_state.is_some() {
            sql.push_str(" AND decrypt_state = ?");
        }
        if query.utxo_id.is_some() {
            sql.push_str(" AND utxo_id = ?");
        }
        if query.after.is_some() {
            sql.push_str(" AND rowid < ?");
        }
        sql.push_str(" ORDER BY rowid DESC LIMIT ?");

        let mut q = sqlx::query(&sql).bind(query.resource_address.to_string());
        if let Some(spend) = query.spend_state {
            q = q.bind(spend.as_str());
        }
        if let Some(decrypt) = query.decrypt_state {
            q = q.bind(decrypt.as_str());
        }
        if let Some(id) = query.utxo_id {
            q = q.bind(id.as_bytes().to_vec());
        }
        if let Some(rowid) = query.after {
            q = q.bind(rowid);
        }
        q = q.bind(query.limit as i64);

        q.fetch_all(&self.pool).await?.iter().map(decode_utxo).collect()
    }

    pub async fn utxo_counts(&self, address: &ResourceAddress) -> Result<UtxoCounts, StoreError> {
        let rows = sqlx::query(
            "SELECT spend_state, decrypt_state, COUNT(*) AS n FROM utxos WHERE resource_address = ? GROUP BY \
             spend_state, decrypt_state",
        )
        .bind(address.to_string())
        .fetch_all(&self.pool)
        .await?;

        let mut counts = UtxoCounts::default();
        for row in rows {
            let n: i64 = row.try_get("n")?;
            let n = n as u64;
            counts.total += n;
            match decode_enum::<SpendState>(&row, "spend_state", "utxos")? {
                SpendState::Unspent => counts.unspent += n,
                SpendState::Spent => counts.spent += n,
                SpendState::Burnt => counts.burnt += n,
            }
            match decode_enum::<DecryptState>(&row, "decrypt_state", "utxos")? {
                DecryptState::Decrypting => counts.decrypting += n,
                DecryptState::Decrypted => counts.decrypted += n,
                DecryptState::Failed => counts.failed += n,
                DecryptState::FailedOutOfRange => counts.failed_out_of_range += n,
                DecryptState::NoCiphertext => counts.no_ciphertext += n,
            }
        }
        Ok(counts)
    }

    // ---------------------------------- decryption ----------------------------------

    /// Rows awaiting decryption: `Decrypting` with a stored ciphertext, oldest first.
    pub async fn list_pending_decrypt(
        &self,
        address: &ResourceAddress,
        limit: u32,
    ) -> Result<Vec<(UtxoId, Vec<u8>)>, StoreError> {
        let rows = sqlx::query(
            "SELECT utxo_id, ciphertext FROM utxos WHERE resource_address = ? AND decrypt_state = ? AND ciphertext IS \
             NOT NULL ORDER BY first_seen_at LIMIT ?",
        )
        .bind(address.to_string())
        .bind(DecryptState::Decrypting.as_str())
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|row| {
                let id: Vec<u8> = row.try_get("utxo_id")?;
                let ciphertext: Vec<u8> = row.try_get("ciphertext")?;
                let id = UtxoId::from_array(id.try_into().map_err(|_| corrupt("utxos", "utxo_id is not 32 bytes"))?);
                Ok((id, ciphertext))
            })
            .collect()
    }

    /// Records per-UTXO decrypt outcomes in one transaction. `coverage_max` is the current
    /// lookup file's upper bound, stamped on out-of-range rows to drive later auto-retry.
    pub async fn record_decrypt_outcomes(
        &self,
        address: &ResourceAddress,
        outcomes: &[(UtxoId, crate::decrypt::DecryptOutcome)],
        coverage_max: u64,
    ) -> Result<(), StoreError> {
        use crate::decrypt::DecryptOutcome;

        let address = address.to_string();
        let now = Utc::now();
        let mut tx = self.pool.begin().await?;
        for (id, outcome) in outcomes {
            let (state, value, fail_lookup_max) = match outcome {
                DecryptOutcome::Value(v) => (DecryptState::Decrypted, Some(*v as i64), None),
                DecryptOutcome::OutOfRange => (DecryptState::FailedOutOfRange, None, Some(coverage_max as i64)),
                DecryptOutcome::Malformed => (DecryptState::Failed, None, None),
            };
            sqlx::query(
                "UPDATE utxos SET decrypt_state = ?, value = ?, fail_lookup_max = ?, updated_at = ? WHERE \
                 resource_address = ? AND utxo_id = ?",
            )
            .bind(state.as_str())
            .bind(value)
            .bind(fail_lookup_max)
            .bind(now)
            .bind(&address)
            .bind(id.as_bytes().as_slice())
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Flips `FailedOutOfRange` rows back to `Decrypting` when the current lookup coverage
    /// exceeds the coverage recorded at their last failed attempt. Returns the number requeued.
    pub async fn requeue_out_of_range(&self, address: &ResourceAddress, coverage_max: u64) -> Result<u64, StoreError> {
        let res = sqlx::query(
            "UPDATE utxos SET decrypt_state = ?, fail_lookup_max = NULL, updated_at = ? WHERE resource_address = ? \
             AND decrypt_state = ? AND ciphertext IS NOT NULL AND (fail_lookup_max IS NULL OR fail_lookup_max < ?)",
        )
        .bind(DecryptState::Decrypting.as_str())
        .bind(Utc::now())
        .bind(address.to_string())
        .bind(DecryptState::FailedOutOfRange.as_str())
        .bind(coverage_max as i64)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    /// Applies one shard batch atomically: upserts freshly-fetched unspent outputs, applies
    /// spend/burn events, and advances the shard's resume cursor. A crash before commit simply
    /// re-streams the batch on the next pass (upserts are idempotent).
    pub async fn apply_shard_batch(
        &self,
        address: &ResourceAddress,
        batch: &ShardBatch,
        new_unspent: &[NewUnspentUtxo],
    ) -> Result<BatchOutcome, StoreError> {
        let address = address.to_string();
        let now = Utc::now();
        let watermark = batch.max_state_version.as_u64() as i64;
        let mut outcome = BatchOutcome::default();

        let mut tx = self.pool.begin().await?;

        for utxo in new_unspent {
            let exists = sqlx::query("SELECT 1 FROM utxos WHERE resource_address = ? AND utxo_id = ?")
                .bind(&address)
                .bind(utxo.id.as_bytes().as_slice())
                .fetch_optional(&mut *tx)
                .await?
                .is_some();

            let decrypt_state = if utxo.ciphertext.is_some() {
                DecryptState::Decrypting
            } else {
                DecryptState::Failed
            };

            // On replay the row may since have been spent — spend_state is deliberately not
            // updated so a re-streamed `Unspent` can never regress a `Spent`/`Burnt` row.
            sqlx::query(
                "INSERT INTO utxos (resource_address, utxo_id, tag, fetch_nonce, ciphertext, spend_state, \
                 decrypt_state, created_state_version, first_seen_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, \
                 ?) ON CONFLICT (resource_address, utxo_id) DO UPDATE SET tag = excluded.tag, fetch_nonce = \
                 excluded.fetch_nonce, ciphertext = COALESCE(utxos.ciphertext, excluded.ciphertext), decrypt_state = \
                 CASE WHEN utxos.ciphertext IS NULL AND excluded.ciphertext IS NOT NULL THEN excluded.decrypt_state \
                 ELSE utxos.decrypt_state END, created_state_version = COALESCE(utxos.created_state_version, \
                 excluded.created_state_version), updated_at = excluded.updated_at",
            )
            .bind(&address)
            .bind(utxo.id.as_bytes().as_slice())
            .bind(utxo.tag.value() as i64)
            .bind(utxo.fetch_nonce.as_bytes())
            .bind(utxo.ciphertext.as_deref())
            .bind(SpendState::Unspent.as_str())
            .bind(decrypt_state.as_str())
            .bind(watermark)
            .bind(now)
            .bind(now)
            .execute(&mut *tx)
            .await?;

            if exists {
                outcome.replayed_unspent += 1;
            } else {
                outcome.inserted_unspent += 1;
            }
        }

        for spend in &batch.spends {
            let exists = sqlx::query("SELECT 1 FROM utxos WHERE resource_address = ? AND utxo_id = ?")
                .bind(&address)
                .bind(spend.id.as_bytes().as_slice())
                .fetch_optional(&mut *tx)
                .await?
                .is_some();

            // An unknown id is an output spent before we ever saw it unspent — the indexer has
            // already pruned its ciphertext, so it can never be valued (DESIGN §2.4).
            sqlx::query(
                "INSERT INTO utxos (resource_address, utxo_id, spend_state, decrypt_state, spent_state_version, \
                 first_seen_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (resource_address, utxo_id) DO \
                 UPDATE SET spend_state = excluded.spend_state, spent_state_version = excluded.spent_state_version, \
                 updated_at = excluded.updated_at",
            )
            .bind(&address)
            .bind(spend.id.as_bytes().as_slice())
            .bind(spend.kind.as_spend_state().as_str())
            .bind(DecryptState::NoCiphertext.as_str())
            .bind(watermark)
            .bind(now)
            .bind(now)
            .execute(&mut *tx)
            .await?;

            if exists {
                outcome.spends_applied += 1;
            } else {
                outcome.unknown_spends += 1;
            }
        }

        // Monotonic: MAX() guards against an out-of-order replay moving the cursor backwards.
        sqlx::query(
            "INSERT INTO shard_cursors (resource_address, shard, state_version) VALUES (?, ?, ?) ON CONFLICT \
             (resource_address, shard) DO UPDATE SET state_version = MAX(shard_cursors.state_version, \
             excluded.state_version)",
        )
        .bind(&address)
        .bind(batch.shard.as_u32() as i64)
        .bind(watermark)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(outcome)
    }
}

const UTXO_COLUMNS: &str = "rowid, resource_address, utxo_id, tag, fetch_nonce, ciphertext, value, spend_state, \
                            decrypt_state, fail_lookup_max, created_epoch, created_state_version, spent_epoch, \
                            spent_state_version, first_seen_at, updated_at";

fn corrupt(table: &'static str, details: impl Into<String>) -> StoreError {
    StoreError::CorruptRow {
        table,
        details: details.into(),
    }
}

fn decode_enum<T: FromStr<Err = String>>(row: &SqliteRow, column: &str, table: &'static str) -> Result<T, StoreError> {
    let raw: String = row.try_get(column)?;
    raw.parse().map_err(|e: String| corrupt(table, e))
}

fn decode_view_key(row: &SqliteRow) -> Result<ViewKeyRow, StoreError> {
    let secret: Vec<u8> = row.try_get("secret")?;
    let public: Vec<u8> = row.try_get("public")?;
    Ok(ViewKeyRow {
        id: row.try_get("id")?,
        label: row.try_get("label")?,
        secret: secret
            .try_into()
            .map_err(|_| corrupt("view_keys", "secret is not 32 bytes"))?,
        public: RistrettoPublicKeyBytes::from_bytes(&public).map_err(|e| corrupt("view_keys", e.to_string()))?,
        created_at: row.try_get("created_at")?,
    })
}

fn decode_resource(row: &SqliteRow) -> Result<ResourceRow, StoreError> {
    let address: String = row.try_get("resource_address")?;
    let divisibility: i64 = row.try_get("divisibility")?;
    let from_epoch: i64 = row.try_get("from_epoch")?;
    Ok(ResourceRow {
        resource_address: ResourceAddress::from_str(&address).map_err(|e| corrupt("resources", e.to_string()))?,
        view_key_id: row.try_get("view_key_id")?,
        divisibility: divisibility as u8,
        from_epoch: from_epoch as u64,
        active: row.try_get("active")?,
        added_at: row.try_get("added_at")?,
    })
}

fn decode_utxo(row: &SqliteRow) -> Result<UtxoRow, StoreError> {
    let address: String = row.try_get("resource_address")?;
    let utxo_id: Vec<u8> = row.try_get("utxo_id")?;
    let tag: Option<i64> = row.try_get("tag")?;
    let fetch_nonce: Option<Vec<u8>> = row.try_get("fetch_nonce")?;
    let value: Option<i64> = row.try_get("value")?;
    let fail_lookup_max: Option<i64> = row.try_get("fail_lookup_max")?;
    let created_epoch: Option<i64> = row.try_get("created_epoch")?;
    let created_state_version: Option<i64> = row.try_get("created_state_version")?;
    let spent_epoch: Option<i64> = row.try_get("spent_epoch")?;
    let spent_state_version: Option<i64> = row.try_get("spent_state_version")?;

    Ok(UtxoRow {
        rowid: row.try_get("rowid")?,
        resource_address: ResourceAddress::from_str(&address).map_err(|e| corrupt("utxos", e.to_string()))?,
        utxo_id: UtxoId::from_array(
            utxo_id
                .try_into()
                .map_err(|_| corrupt("utxos", "utxo_id is not 32 bytes"))?,
        ),
        tag: tag.map(|t| UtxoTag::new(t as u32)),
        fetch_nonce: fetch_nonce
            .map(|b| RistrettoPublicKeyBytes::from_bytes(&b).map_err(|e| corrupt("utxos", e.to_string())))
            .transpose()?,
        ciphertext: row.try_get("ciphertext")?,
        value: value.map(|v| v as u64),
        spend_state: decode_enum(row, "spend_state", "utxos")?,
        decrypt_state: decode_enum(row, "decrypt_state", "utxos")?,
        fail_lookup_max: fail_lookup_max.map(|v| v as u64),
        created_epoch: created_epoch.map(|v| v as u64),
        created_state_version: created_state_version.map(|v| v as u64),
        spent_epoch: spent_epoch.map(|v| v as u64),
        spent_state_version: spent_state_version.map(|v| v as u64),
        first_seen_at: row.try_get("first_seen_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}
