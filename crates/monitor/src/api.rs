// Copyright 2026 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! REST API (DESIGN §9). All routes are mounted under `/api` and share a [`Monitor`] as state, so
//! resources and view keys can be added, enabled, and disabled while ingestion runs.

use std::str::FromStr;

use axum::{
    Json,
    Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use serde::{Deserialize, Serialize};
use tari_template_lib_types::{ResourceAddress, UtxoId};
use utxo_monitor_core::{
    keys::ViewKeyPair,
    monitor::{Monitor, MonitorError},
    store::{UtxoCounts, UtxoQuery},
    types::{DecryptState, ResourceRow, SpendState, UtxoRow, ViewKeyRow},
};

pub fn router(monitor: Monitor) -> Router {
    Router::new()
        .route("/view-keys", get(list_view_keys).post(create_view_key))
        .route("/view-keys/{id}", delete(delete_view_key))
        .route("/view-keys/{id}/secret", get(reveal_view_key))
        .route("/resources", get(list_resources).post(add_resource))
        .route("/resources/{address}/enable", post(enable_resource))
        .route("/resources/{address}/disable", post(disable_resource))
        .route("/utxos", get(list_utxos))
        .route("/reprocess-failed", post(reprocess_failed))
        .route("/status", get(status))
        .with_state(monitor)
}

// ---------------------------------- error handling ----------------------------------

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(serde_json::json!({ "error": self.message }))).into_response()
    }
}

impl From<MonitorError> for ApiError {
    fn from(err: MonitorError) -> Self {
        let status = match &err {
            MonitorError::Validation(_) => StatusCode::BAD_REQUEST,
            MonitorError::ViewKeyNotFound(_) => StatusCode::NOT_FOUND,
            MonitorError::ViewKeyInUse { .. } => StatusCode::CONFLICT,
            MonitorError::Provider(_) => StatusCode::BAD_GATEWAY,
            MonitorError::Store(e) if e.is_not_found() => StatusCode::NOT_FOUND,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        ApiError::new(status, err.to_string())
    }
}

type ApiResult<T> = Result<T, ApiError>;

fn parse_resource(raw: &str) -> ApiResult<ResourceAddress> {
    ResourceAddress::from_str(raw)
        .map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, format!("invalid resource address: {e}")))
}

// ---------------------------------- DTOs ----------------------------------

#[derive(Serialize)]
struct ViewKeyDto {
    id: i64,
    label: String,
    public: String,
    created_at: String,
}

impl From<ViewKeyRow> for ViewKeyDto {
    fn from(row: ViewKeyRow) -> Self {
        Self {
            id: row.id,
            label: row.label,
            public: hex::encode(row.public.as_bytes()),
            created_at: row.created_at.to_rfc3339(),
        }
    }
}

#[derive(Deserialize)]
struct CreateViewKey {
    label: String,
    /// 32-byte Ristretto scalar in hex; a fresh key is generated when omitted.
    secret_hex: Option<String>,
}

#[derive(Serialize)]
struct SecretDto {
    secret_hex: String,
}

#[derive(Deserialize)]
struct AddResource {
    resource_address: String,
}

#[derive(Serialize)]
struct ResourceDto {
    address: String,
    view_key_id: i64,
    divisibility: u8,
    from_epoch: u64,
    active: bool,
    running: bool,
    counts: CountsDto,
}

#[derive(Serialize, Default)]
struct CountsDto {
    total: u64,
    unspent: u64,
    spent: u64,
    burnt: u64,
    decrypting: u64,
    decrypted: u64,
    failed: u64,
    failed_out_of_range: u64,
    no_ciphertext: u64,
}

impl From<UtxoCounts> for CountsDto {
    fn from(c: UtxoCounts) -> Self {
        Self {
            total: c.total,
            unspent: c.unspent,
            spent: c.spent,
            burnt: c.burnt,
            decrypting: c.decrypting,
            decrypted: c.decrypted,
            failed: c.failed,
            failed_out_of_range: c.failed_out_of_range,
            no_ciphertext: c.no_ciphertext,
        }
    }
}

#[derive(Serialize)]
struct UtxoDto {
    utxo_id: String,
    value: Option<u64>,
    spend_state: String,
    decrypt_state: String,
    tag: Option<u32>,
    created_state_version: Option<u64>,
    spent_state_version: Option<u64>,
    first_seen_at: String,
}

impl From<UtxoRow> for UtxoDto {
    fn from(row: UtxoRow) -> Self {
        Self {
            utxo_id: row.utxo_id.to_string(),
            value: row.value,
            spend_state: row.spend_state.as_str().to_string(),
            decrypt_state: row.decrypt_state.as_str().to_string(),
            tag: row.tag.map(|t| t.value()),
            created_state_version: row.created_state_version,
            spent_state_version: row.spent_state_version,
            first_seen_at: row.first_seen_at.to_rfc3339(),
        }
    }
}

#[derive(Deserialize)]
struct UtxoListParams {
    resource: String,
    spend_state: Option<String>,
    decrypt_state: Option<String>,
    utxo_id: Option<String>,
    limit: Option<u32>,
    cursor: Option<String>,
}

#[derive(Serialize)]
struct UtxoPage {
    items: Vec<UtxoDto>,
    next_cursor: Option<String>,
}

#[derive(Deserialize)]
struct ReprocessParams {
    resource: Option<String>,
}

// ---------------------------------- handlers ----------------------------------

async fn list_view_keys(State(monitor): State<Monitor>) -> ApiResult<Json<Vec<ViewKeyDto>>> {
    let keys = monitor.list_view_keys().await?;
    Ok(Json(keys.into_iter().map(ViewKeyDto::from).collect()))
}

async fn create_view_key(
    State(monitor): State<Monitor>,
    Json(body): Json<CreateViewKey>,
) -> ApiResult<Json<ViewKeyDto>> {
    let label = body.label.trim();
    if label.is_empty() {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "label must not be empty"));
    }
    let pair = match &body.secret_hex {
        Some(hex_str) => {
            ViewKeyPair::from_secret_hex(hex_str).map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, e.to_string()))?
        },
        None => ViewKeyPair::generate(),
    };
    let row = monitor.add_view_key(label, &pair.secret_bytes(), &pair.public).await?;
    Ok(Json(row.into()))
}

async fn reveal_view_key(State(monitor): State<Monitor>, Path(id): Path<i64>) -> ApiResult<Json<SecretDto>> {
    let key = monitor
        .list_view_keys()
        .await?
        .into_iter()
        .find(|k| k.id == id)
        .ok_or(MonitorError::ViewKeyNotFound(id))?;
    Ok(Json(SecretDto {
        secret_hex: hex::encode(key.secret),
    }))
}

async fn delete_view_key(State(monitor): State<Monitor>, Path(id): Path<i64>) -> ApiResult<StatusCode> {
    monitor.delete_view_key(id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn resource_dto(monitor: &Monitor, row: ResourceRow) -> ApiResult<ResourceDto> {
    let counts = monitor.resource_counts(&row.resource_address).await?;
    Ok(ResourceDto {
        address: row.resource_address.to_string(),
        view_key_id: row.view_key_id,
        divisibility: row.divisibility,
        from_epoch: row.from_epoch,
        active: row.active,
        running: monitor.is_running(&row.resource_address),
        counts: counts.into(),
    })
}

async fn list_resources(State(monitor): State<Monitor>) -> ApiResult<Json<Vec<ResourceDto>>> {
    let rows = monitor.list_resources().await?;
    let mut dtos = Vec::with_capacity(rows.len());
    for row in rows {
        dtos.push(resource_dto(&monitor, row).await?);
    }
    Ok(Json(dtos))
}

async fn add_resource(State(monitor): State<Monitor>, Json(body): Json<AddResource>) -> ApiResult<Json<ResourceDto>> {
    let address = parse_resource(&body.resource_address)?;
    let row = monitor.add_resource(address).await?;
    Ok(Json(resource_dto(&monitor, row).await?))
}

async fn enable_resource(State(monitor): State<Monitor>, Path(address): Path<String>) -> ApiResult<StatusCode> {
    monitor.enable_resource(&parse_resource(&address)?).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn disable_resource(State(monitor): State<Monitor>, Path(address): Path<String>) -> ApiResult<StatusCode> {
    monitor.disable_resource(&parse_resource(&address)?).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_utxos(State(monitor): State<Monitor>, Query(params): Query<UtxoListParams>) -> ApiResult<Json<UtxoPage>> {
    let resource = parse_resource(&params.resource)?;
    let limit = params.limit.unwrap_or(100).clamp(1, 1000);

    let spend_state = params
        .spend_state
        .as_deref()
        .map(|s| s.parse::<SpendState>())
        .transpose()
        .map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, e))?;
    let decrypt_state = params
        .decrypt_state
        .as_deref()
        .map(|s| s.parse::<DecryptState>())
        .transpose()
        .map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, e))?;
    let utxo_id = params.utxo_id.as_deref().map(parse_utxo_id).transpose()?;
    let after = params.cursor.as_deref().map(decode_cursor).transpose()?;

    // Fetch one extra row to determine whether a further page exists.
    let query = UtxoQuery {
        resource_address: &resource,
        spend_state,
        decrypt_state,
        utxo_id,
        after,
        limit: limit + 1,
    };
    let mut rows = monitor.store().query_utxos(&query).await.map_err(MonitorError::from)?;

    let next_cursor = if rows.len() as u32 > limit {
        rows.truncate(limit as usize);
        rows.last().map(encode_cursor)
    } else {
        None
    };

    Ok(Json(UtxoPage {
        items: rows.into_iter().map(UtxoDto::from).collect(),
        next_cursor,
    }))
}

async fn reprocess_failed(
    State(monitor): State<Monitor>,
    Query(params): Query<ReprocessParams>,
) -> ApiResult<Json<serde_json::Value>> {
    let resources = match &params.resource {
        Some(raw) => vec![parse_resource(raw)?],
        None => monitor
            .list_resources()
            .await?
            .into_iter()
            .map(|r| r.resource_address)
            .collect(),
    };
    let mut requeued = 0u64;
    for address in resources {
        requeued += monitor.reprocess_failed(&address).await?;
    }
    Ok(Json(serde_json::json!({ "requeued": requeued })))
}

#[derive(Serialize)]
struct StatusDto {
    lookup: LookupDto,
    workers_available: usize,
    resources: Vec<ResourceStatusDto>,
}

#[derive(Serialize)]
struct LookupDto {
    path: String,
    min: u64,
    max: u64,
    num_records: usize,
}

#[derive(Serialize)]
struct ResourceStatusDto {
    address: String,
    active: bool,
    running: bool,
    counts: CountsDto,
}

async fn status(State(monitor): State<Monitor>) -> ApiResult<Json<StatusDto>> {
    let lookup = monitor.lookup();
    let range = lookup.range();

    let mut resources = Vec::new();
    for row in monitor.list_resources().await? {
        let counts = monitor.resource_counts(&row.resource_address).await?;
        resources.push(ResourceStatusDto {
            address: row.resource_address.to_string(),
            active: row.active,
            running: monitor.is_running(&row.resource_address),
            counts: counts.into(),
        });
    }

    Ok(Json(StatusDto {
        lookup: LookupDto {
            path: lookup.path().to_string(),
            min: *range.start(),
            max: *range.end(),
            num_records: lookup.num_records(),
        },
        workers_available: monitor.available_decrypt_workers(),
        resources,
    }))
}

// ---------------------------------- keyset cursor ----------------------------------

fn parse_utxo_id(raw: &str) -> ApiResult<UtxoId> {
    let trimmed = raw.trim();
    let hex_part = trimmed.strip_prefix("utxo_").unwrap_or(trimmed);
    UtxoId::from_hex(hex_part).map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, format!("invalid utxo_id: {e}")))
}

/// Opaque cursor over the row's `rowid` (discovery order).
fn encode_cursor(row: &UtxoRow) -> String {
    row.rowid.to_string()
}

fn decode_cursor(raw: &str) -> ApiResult<i64> {
    let cursor = raw
        .parse::<i64>()
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "malformed cursor"))?;
    if cursor <= 0 {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "malformed cursor"));
    }
    Ok(cursor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_utxo_id_accepts_both_raw_hex_and_prefixed_display_form() {
        let id = UtxoId::from_array([0xAB; 32]);
        let display_str = id.to_string();
        assert_eq!(parse_utxo_id(&display_str).unwrap(), id);
        assert_eq!(parse_utxo_id(&hex::encode([0xAB; 32])).unwrap(), id);
    }

    #[test]
    fn decode_cursor_rejects_non_positive_and_non_numeric_values() {
        assert_eq!(decode_cursor("1").unwrap(), 1);
        assert_eq!(decode_cursor("42").unwrap(), 42);
        assert!(decode_cursor("0").is_err());
        assert!(decode_cursor("-5").is_err());
        assert!(decode_cursor("abc").is_err());
    }
}
