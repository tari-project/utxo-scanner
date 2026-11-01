// Copyright 2026 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use tari_template_lib_types::ObjectKey;

use super::*;
use crate::{
    decrypt::DecryptOutcome,
    error::Optional,
    test_utils::{new_unspent, nonce, store_with_resource, utxo_id},
    types::{NewUnspentUtxo, ShardBatch, SpendEvent, SpendKind},
};

fn batch(shard: u32, watermark: u64) -> ShardBatch {
    ShardBatch {
        shard: Shard::from(shard),
        max_state_version: StateVersion::new(watermark),
        num_updates: 0,
        unspent: Vec::new(),
        spends: Vec::new(),
    }
}

fn spend(n: u8, kind: SpendKind) -> SpendEvent {
    SpendEvent {
        id: utxo_id(n),
        kind,
        substate_version: 1,
    }
}

#[tokio::test]
async fn view_key_roundtrip_and_not_found() {
    let store = Store::in_memory().await.unwrap();
    assert!(store.get_view_key(1).await.unwrap_err().is_not_found());
    assert!(store.get_view_key(1).await.optional().unwrap().is_none());

    let inserted = store.insert_view_key("main", &[3u8; 32], &nonce(4)).await.unwrap();
    let fetched = store.get_view_key(inserted.id).await.unwrap();
    assert_eq!(fetched.label, "main");
    assert_eq!(fetched.secret, [3u8; 32]);
    assert_eq!(fetched.public, nonce(4));

    let all = store.list_view_keys().await.unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].id, inserted.id);
}

#[tokio::test]
async fn resource_insert_is_idempotent_and_active_toggles() {
    let (store, address) = store_with_resource().await;

    // Re-adding the same resource is a no-op, not an error.
    let key_id = store.get_resource(&address).await.unwrap().view_key_id;
    store.insert_resource(&address, key_id, 9, 5).await.unwrap();
    let row = store.get_resource(&address).await.unwrap();
    assert_eq!(row.divisibility, 6);
    assert_eq!(row.from_epoch, 0);
    assert!(row.active);

    store.set_resource_active(&address, false).await.unwrap();
    assert!(store.list_active_resources().await.unwrap().is_empty());
    assert_eq!(store.list_resources().await.unwrap().len(), 1);

    let missing = ResourceAddress::new(ObjectKey::from_array([8u8; ObjectKey::LENGTH]));
    assert!(
        store
            .set_resource_active(&missing, true)
            .await
            .unwrap_err()
            .is_not_found()
    );
}

#[tokio::test]
async fn apply_batch_inserts_unspent_rows_and_advances_cursor() {
    let (store, address) = store_with_resource().await;

    let mut b = batch(3, 42);
    let new_rows = [new_unspent(1), new_unspent(2)];
    b.num_updates = 2;
    let outcome = store.apply_shard_batch(&address, &b, &new_rows).await.unwrap();

    assert_eq!(outcome.inserted_unspent, 2);
    assert_eq!(outcome.replayed_unspent, 0);
    assert_eq!(outcome.spends_applied, 0);
    assert_eq!(outcome.unknown_spends, 0);

    let row = store.get_utxo(&address, &utxo_id(1)).await.unwrap();
    assert_eq!(row.spend_state, SpendState::Unspent);
    assert_eq!(row.decrypt_state, DecryptState::Decrypting);
    assert_eq!(row.ciphertext.as_deref(), Some(vec![1u8; 64].as_slice()));
    assert_eq!(row.fetch_nonce, Some(nonce(1)));
    assert_eq!(row.created_state_version, Some(42));
    assert_eq!(row.value, None);

    let cursor = store.load_shard_cursor(&address).await.unwrap();
    assert_eq!(cursor.get(Shard::from(3)), StateVersion::new(42));
    // Only the batch's shard is tracked.
    assert_eq!(cursor.to_pairs().len(), 1);
}

#[tokio::test]
async fn missing_viewable_balance_is_a_hard_failure() {
    let (store, address) = store_with_resource().await;

    let no_balance = NewUnspentUtxo {
        ciphertext: None,
        ..new_unspent(1)
    };
    store
        .apply_shard_batch(&address, &batch(1, 10), &[no_balance])
        .await
        .unwrap();

    let row = store.get_utxo(&address, &utxo_id(1)).await.unwrap();
    assert_eq!(row.decrypt_state, DecryptState::Failed);
    assert_eq!(row.ciphertext, None);
}

#[tokio::test]
async fn spend_of_known_row_preserves_ciphertext() {
    let (store, address) = store_with_resource().await;
    store
        .apply_shard_batch(&address, &batch(1, 10), &[new_unspent(1)])
        .await
        .unwrap();

    let mut spend_batch = batch(1, 20);
    spend_batch.spends.push(spend(1, SpendKind::Spent));
    let outcome = store.apply_shard_batch(&address, &spend_batch, &[]).await.unwrap();
    assert_eq!(outcome.spends_applied, 1);
    assert_eq!(outcome.unknown_spends, 0);

    let row = store.get_utxo(&address, &utxo_id(1)).await.unwrap();
    assert_eq!(row.spend_state, SpendState::Spent);
    // The stored ciphertext and decrypt progress survive the spend.
    assert_eq!(row.decrypt_state, DecryptState::Decrypting);
    assert_eq!(row.ciphertext.as_deref(), Some(vec![1u8; 64].as_slice()));
    assert_eq!(row.spent_state_version, Some(20));
}

#[tokio::test]
async fn spend_of_unknown_row_inserts_no_ciphertext() {
    let (store, address) = store_with_resource().await;

    let mut b = batch(1, 30);
    b.spends.push(spend(9, SpendKind::Burnt));
    let outcome = store.apply_shard_batch(&address, &b, &[]).await.unwrap();
    assert_eq!(outcome.unknown_spends, 1);
    assert_eq!(outcome.spends_applied, 0);

    let row = store.get_utxo(&address, &utxo_id(9)).await.unwrap();
    assert_eq!(row.spend_state, SpendState::Burnt);
    assert_eq!(row.decrypt_state, DecryptState::NoCiphertext);
    assert_eq!(row.ciphertext, None);
    assert_eq!(row.value, None);
    assert_eq!(row.tag, None);
}

#[tokio::test]
async fn replayed_unspent_does_not_regress_a_spent_row() {
    let (store, address) = store_with_resource().await;

    // First pass: seen unspent, then spent.
    store
        .apply_shard_batch(&address, &batch(1, 10), &[new_unspent(1)])
        .await
        .unwrap();
    let mut spend_batch = batch(1, 20);
    spend_batch.spends.push(spend(1, SpendKind::Spent));
    store.apply_shard_batch(&address, &spend_batch, &[]).await.unwrap();

    // Crash-replay of the original batch: the fetch also (unrealistically) still returns the
    // output. The row must stay Spent.
    let outcome = store
        .apply_shard_batch(&address, &batch(1, 10), &[new_unspent(1)])
        .await
        .unwrap();
    assert_eq!(outcome.replayed_unspent, 1);
    assert_eq!(outcome.inserted_unspent, 0);

    let row = store.get_utxo(&address, &utxo_id(1)).await.unwrap();
    assert_eq!(row.spend_state, SpendState::Spent);
}

#[tokio::test]
async fn unspent_after_unknown_spend_backfills_created_version_and_ciphertext() {
    let (store, address) = store_with_resource().await;

    // First seen as a spend before its unspent output is observed.
    let mut spend_batch = batch(1, 20);
    spend_batch.spends.push(spend(1, SpendKind::Spent));
    store.apply_shard_batch(&address, &spend_batch, &[]).await.unwrap();

    // Later replay of the unspent output must preserve SpendState::Spent while backfilling
    // created_state_version, ciphertext, and DecryptState::Decrypting.
    let outcome = store
        .apply_shard_batch(&address, &batch(1, 10), &[new_unspent(1)])
        .await
        .unwrap();
    assert_eq!(outcome.replayed_unspent, 1);

    let row = store.get_utxo(&address, &utxo_id(1)).await.unwrap();
    assert_eq!(row.spend_state, SpendState::Spent);
    assert_eq!(row.created_state_version, Some(10));
    assert_eq!(row.spent_state_version, Some(20));
    assert_eq!(row.decrypt_state, DecryptState::Decrypting);
}

#[tokio::test]
async fn cursor_is_monotonic() {
    let (store, address) = store_with_resource().await;

    store.apply_shard_batch(&address, &batch(1, 50), &[]).await.unwrap();
    store.apply_shard_batch(&address, &batch(1, 40), &[]).await.unwrap();

    let cursor = store.load_shard_cursor(&address).await.unwrap();
    assert_eq!(cursor.get(Shard::from(1)), StateVersion::new(50));
}

#[tokio::test]
async fn decrypt_outcomes_transition_rows_and_are_paged() {
    let (store, address) = store_with_resource().await;
    store
        .apply_shard_batch(&address, &batch(1, 10), &[
            new_unspent(1),
            new_unspent(2),
            new_unspent(3),
        ])
        .await
        .unwrap();

    let pending = store.list_pending_decrypt(&address, 100).await.unwrap();
    assert_eq!(pending.len(), 3);

    store
        .record_decrypt_outcomes(
            &address,
            &[
                (utxo_id(1), DecryptOutcome::Value(500)),
                (utxo_id(2), DecryptOutcome::OutOfRange),
                (utxo_id(3), DecryptOutcome::Malformed),
            ],
            1000,
        )
        .await
        .unwrap();

    let decrypted = store.get_utxo(&address, &utxo_id(1)).await.unwrap();
    assert_eq!(decrypted.decrypt_state, DecryptState::Decrypted);
    assert_eq!(decrypted.value, Some(500));

    let oor = store.get_utxo(&address, &utxo_id(2)).await.unwrap();
    assert_eq!(oor.decrypt_state, DecryptState::FailedOutOfRange);
    assert_eq!(oor.fail_lookup_max, Some(1000));
    assert_eq!(oor.value, None);

    let hard = store.get_utxo(&address, &utxo_id(3)).await.unwrap();
    assert_eq!(hard.decrypt_state, DecryptState::Failed);

    // Nothing left to decrypt.
    assert!(store.list_pending_decrypt(&address, 100).await.unwrap().is_empty());
}

#[tokio::test]
async fn requeue_out_of_range_only_widens_coverage() {
    let (store, address) = store_with_resource().await;
    store
        .apply_shard_batch(&address, &batch(1, 10), &[new_unspent(1)])
        .await
        .unwrap();
    store
        .record_decrypt_outcomes(&address, &[(utxo_id(1), DecryptOutcome::OutOfRange)], 1000)
        .await
        .unwrap();

    // A file with the same coverage does not requeue.
    assert_eq!(store.requeue_out_of_range(&address, 1000).await.unwrap(), 0);
    assert_eq!(
        store.get_utxo(&address, &utxo_id(1)).await.unwrap().decrypt_state,
        DecryptState::FailedOutOfRange
    );

    // A wider file requeues the row for another attempt.
    assert_eq!(store.requeue_out_of_range(&address, 5000).await.unwrap(), 1);
    let row = store.get_utxo(&address, &utxo_id(1)).await.unwrap();
    assert_eq!(row.decrypt_state, DecryptState::Decrypting);
    assert_eq!(row.fail_lookup_max, None);
    assert_eq!(store.list_pending_decrypt(&address, 100).await.unwrap().len(), 1);
}

#[tokio::test]
async fn query_utxos_orders_by_discovery_not_state_version() {
    let (store, address) = store_with_resource().await;

    // Discover utxo 1 first, in a shard with a HIGH state version; then utxo 2, in a shard with a
    // LOWER state version. Per-shard state versions are not globally monotonic, so discovery order
    // (utxo 2 newest) must win over state-version order.
    store
        .apply_shard_batch(&address, &batch(1, 9000), &[new_unspent(1)])
        .await
        .unwrap();
    store
        .apply_shard_batch(&address, &batch(2, 10), &[new_unspent(2)])
        .await
        .unwrap();

    let page1 = store
        .query_utxos(&UtxoQuery {
            limit: 1,
            ..UtxoQuery::new(&address)
        })
        .await
        .unwrap();
    assert_eq!(page1.len(), 1);
    assert_eq!(page1[0].utxo_id, utxo_id(2), "most recently discovered comes first");

    // Keyset page 2 by the last row's rowid.
    let page2 = store
        .query_utxos(&UtxoQuery {
            limit: 1,
            after: Some(page1[0].rowid),
            ..UtxoQuery::new(&address)
        })
        .await
        .unwrap();
    assert_eq!(page2.len(), 1);
    assert_eq!(page2[0].utxo_id, utxo_id(1));
    assert!(page2[0].rowid < page1[0].rowid);
}

#[tokio::test]
async fn utxo_counts_group_both_axes() {
    let (store, address) = store_with_resource().await;

    store
        .apply_shard_batch(&address, &batch(1, 10), &[new_unspent(1), new_unspent(2)])
        .await
        .unwrap();
    let mut b = batch(1, 20);
    b.spends.push(spend(2, SpendKind::Spent));
    b.spends.push(spend(3, SpendKind::Burnt));
    store.apply_shard_batch(&address, &b, &[]).await.unwrap();

    let counts = store.utxo_counts(&address).await.unwrap();
    assert_eq!(counts.total, 3);
    assert_eq!(counts.unspent, 1);
    assert_eq!(counts.spent, 1);
    assert_eq!(counts.burnt, 1);
    assert_eq!(counts.decrypting, 2);
    assert_eq!(counts.no_ciphertext, 1);
}
