# Rust‑Native Sub‑Millisecond LLM Security Gateway

## Phase 4 – Authentication, Governance, and Audit Logging

### New Environment Variables
| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `REQUIRE_AUTH` | When set to `true`, the gateway requires every incoming request to contain a valid `Authorization: Bearer <TOKEN>` header. | `false` | `REQUIRE_AUTH=true` |
| `AUTH_TOKEN` | The token that must be presented in the `Authorization` header when `REQUIRE_AUTH` is enabled. | (none) | `AUTH_TOKEN=super‑secret-token` |
| `GOVERNANCE_DEFAULT_DENY` | Enables the *default‑deny* policy. When `true`, any request that does not match an entry in the allow‑list is blocked. | `true` | `GOVERNANCE_DEFAULT_DENY=true` |
| `GOVERNANCE_ALLOWLIST` | A comma‑separated list of upstream base URLs that are permitted when `GOVERNANCE_DEFAULT_DENY` is `true`. | empty | `GOVERNANCE_ALLOWLIST=http://127.0.0.1:11434,https://api.openai.com` |

### `ThreatCategory` Enum
The gateway now includes a `ThreatCategory` enumeration used by the governance layer to classify the type of request being evaluated.

```rust
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ThreatCategory {
    /// Outbound network access to an upstream LLM service.
    NetworkAccess,
    /// Execution of user‑provided tooling or plugins.
    ToolExecution,
    /// Access to the internal MCP (Model‑Control‑Plane) server.
    McpServer,
    /// Requests that involve Retrieval‑Augmented Generation pipelines.
    RagPipeline,
}
```

The `GovernanceConfig::check_request` method receives a `ThreatCategory` and the target URL (e.g., the upstream base URL). It applies the default‑deny/allow‑list policy and returns `Ok(())` if the request is permitted or a `GatewayError::SecurityBlocked` if it is denied.

### How the Checks are Applied
Both request handlers (`/v1/chat/completions` and `/chat`) now:
1. Extract the request headers via Axum's `Headers` extractor.
2. Call `state.config.security.enforce_auth(&headers)` – aborts with a `403`‑like error if authentication fails.
3. Call `state.config.governance.check_request(ThreatCategory::NetworkAccess, &state.config.upstream.base_url)` – aborts with a `403`‑like error when the URL is not on the allow‑list while default‑deny is active.
4. Log successful authentication and allowed governance decisions with `info!`.

The rest of the request flow (injection scanning, PII/secret redaction, upstream forwarding) remains unchanged.

---

For further details on configuration loading, see `gateway-server/src/config.rs`.

---

## Phase 5 – Retrieval‑Augmented Generation (RAG)

Phase 5 adds an optional, zero-overhead RAG layer to the gateway.  
When disabled (the default), no engine is initialised and there is no runtime cost.  
When enabled, every request can be enriched with semantically relevant context retrieved from a local HNSW vector index before being forwarded to the upstream LLM.

---

### Architecture overview

```
 Client request
      │
      ▼
 Injection scanner  ──block──▶  403 SecurityBlocked
      │ allow
      ▼
 RAG enabled?
  ├─ no  ──────────────────────────────────────────────────────┐
  └─ yes                                                        │
      │                                                         │
      ▼                                                         │
 Governance check (RagPipeline)  ──block──▶  403               │
      │ allow                                                   │
      ▼                                                         │
 RagEngine::search(query_embedding)                             │
      │                                                         │
      ▼                                                         │
 Inject top‑k context into prompt ◀──────────────────────────┘
      │
      ▼
 Upstream LLM  ──▶  PII / secret redaction  ──▶  Client response
```

**Key types**

| Type | Crate | Purpose |
|------|-------|---------|
| `RagConfig` | `gateway_server::rag` | Serialisable configuration; also re-exported from `gateway_server::config` |
| `RagEngine` | `gateway_server::rag` | HNSW index wrapper; created once at startup when RAG is enabled |
| `AppState.config.rag` | `gateway_server::proxy` | Access pattern used in handlers: `state.config.rag.vector_dim` |
| `ThreatCategory::RagPipeline` | `gateway_server::config` | Governance category for RAG requests |

---

### `RagConfig` reference

```rust
pub struct RagConfig {
    /// Enable RAG. When false the engine is never created (zero cost).
    pub enabled: bool,
    /// Dimension of embedding vectors – must match the embedding model.
    /// Default: 384 (all-MiniLM-L6-v2).
    pub vector_dim: usize,
    /// Number of nearest neighbours returned per query. Default: 3.
    pub top_k: usize,
    /// Directory where the HNSW binary index and doc-map JSON are stored.
    pub index_path: PathBuf,
    /// Embedding model identifier (informational; used by the ingest binary).
    pub embedding_model: String,
}
```

**Defaults**

| Field | Default value |
|-------|---------------|
| `enabled` | `false` |
| `vector_dim` | `384` |
| `top_k` | `3` |
| `index_path` | `./rag_index` |
| `embedding_model` | `"all-MiniLM-L6-v2"` |

---

### Configuring RAG

#### `config.toml`

Add a `[rag]` table to your `config.toml`:

```toml
[rag]
enabled       = true
vector_dim    = 384
top_k         = 5
index_path    = "./rag_index"
embedding_model = "all-MiniLM-L6-v2"
```

#### Environment variables

All RAG settings can be overridden at runtime:

| Variable | Description | Default |
|----------|-------------|---------|
| `RAG_ENABLED` | Set `true` to activate the RAG engine. | `false` |
| `RAG_VECTOR_DIM` | Embedding dimension (must match the model). | `384` |
| `RAG_TOP_K` | Number of context chunks injected per request. | `3` |
| `RAG_INDEX_PATH` | Filesystem path for the HNSW index directory. | `./rag_index` |
| `RAG_EMBEDDING_MODEL` | Embedding model name (used by the ingest binary). | `all-MiniLM-L6-v2` |
| `RAG_DOCS_DIR` | Directory scanned for `.txt` documents during ingestion. | `./documents` |

> **Note** – Environment variables take precedence over `config.toml` values, consistent with the rest of the gateway configuration.

---

### Ingesting documents

Use the bundled `ingest` binary to build (or update) the vector index from a directory of plain-text files:

```bash
# 1. Place your .txt documents in the documents directory
mkdir -p documents
cp my_docs/*.txt documents/

# 2. Run the ingestion binary (reads config.toml + RAG_DOCS_DIR)
RAG_DOCS_DIR=./documents cargo run --bin ingest

# 3. Verify the index artefacts were created
ls rag_index*          # rag_index (binary HNSW) + rag_index.json (doc map)
```

**What the ingest binary does**

1. Loads `AppConfig` (with the `[rag]` section).
2. Calls `RagEngine::load(&config.rag)` – creates a fresh HNSW index or loads an existing one.
3. Walks every `*.txt` file under `RAG_DOCS_DIR`.
4. Generates embeddings using the configured `SentenceEmbeddingsModel` (MiniLM-L6-v2 by default).
5. Inserts each `(embedding_vector, doc_id)` pair into the HNSW index.
6. Persists the binary HNSW index to `index_path` and the doc-ID → text map to `<index_path>.json`.

Re-running the binary appends new documents; existing document IDs are preserved.

---

### Handler access pattern

Inside any Axum handler the RAG configuration is reached via the shared `AppState`:

```rust
// Check if RAG is enabled before touching the engine
if state.config.rag.enabled {
    // Access the configured vector dimension
    let dim = state.config.rag.vector_dim;          // e.g. 384

    // Apply the governance gate before performing retrieval
    state.config.governance.check_request(
        ThreatCategory::RagPipeline,
        "rag://internal",
    )?;

    // Search the index with a pre-computed query embedding
    let context_chunks: Vec<String> = rag_engine.search(&query_vec).await;
}
```

The critical Phase 5 access pattern is:

```
state  →  .config  →  .rag  →  .vector_dim   (usize)
                              .top_k          (usize)
                              .enabled        (bool)
                              .index_path     (PathBuf)
                              .embedding_model (String)
```

---

### Governance gating for RAG

The `RagPipeline` variant of `ThreatCategory` lets the governance layer independently control RAG retrieval:

```toml
# config.toml – allow the internal RAG pipeline
[governance]
default_deny = true
allowlist    = ["http://127.0.0.1:11434", "rag://internal"]
```

With `default_deny = true` and `"rag://internal"` on the allowlist, RAG retrieval is permitted while all other unknown targets remain blocked.

---

### Test coverage

Phase 5 ships with two test suites:

#### Unit tests — `gateway-server/src/rag.rs`

| Test | What it verifies |
|------|-----------------|
| `test_rag_config_defaults` | All `RagConfig::default()` values |
| `test_rag_config_custom_fields` | Custom field construction |
| `test_rag_config_clone` | `Clone` derive |
| `test_rag_config_serde_roundtrip` | JSON serialize → deserialize fidelity |
| `test_rag_engine_load_fresh_index` | Fresh engine starts with zero documents |
| `test_rag_engine_model_name_and_top_k_stored` | Config values carried into engine |
| `test_rag_engine_insert_doc` | Single document insert and read-back |
| `test_rag_engine_multiple_docs_inserted` | Batch document insert |
| `test_rag_engine_search_empty_returns_nothing` | Search on empty index |
| `test_rag_engine_search_finds_inserted_doc` | Nearest-neighbour retrieval |
| `test_rag_engine_search_top_k_respected` | Result count bounded by `top_k` |
| `test_rag_engine_search_only_returns_known_docs` | Missing doc-map entries filtered |

#### Integration tests — `gateway-server/tests/rag_integration.rs`

| Test group | Coverage |
|------------|----------|
| **AppConfig RAG field** | `state.config.rag.vector_dim` access chain; disabled-by-default; enable override |
| **Ingestion pipeline** | Fresh engine empty; single doc; multi-doc unique IDs; JSON doc-map round-trip; empty map round-trip |
| **RAG request path** | `vector_dim` from state config; async search returns relevant docs; disabled-RAG guard |
| **Governance** | `RagPipeline` allowed (deny off); blocked (deny on); allowed via allowlist |
| **top_k boundaries** | `top_k = 0` returns empty; `top_k > corpus` returns all available docs |

Run the full suite:

```bash
cargo test -p gateway-server
```

---

### New public API surface (Phase 5)

| Symbol | Location | Notes |
|--------|----------|-------|
| `RagConfig` | `gateway_server::rag` | Serialisable; also in `gateway_server::config` |
| `RagEngine` | `gateway_server::rag` | `load(&RagConfig)` + `async search(&[f32])` |
| `RagEngine::index` | `gateway_server::rag` | `pub` HNSW index (insert during ingestion) |
| `RagEngine::docs` | `gateway_server::rag` | `pub` doc-ID → text map |
| `RagEngine::model_name` | `gateway_server::rag` | `pub` embedding model identifier |
| `RagEngine::top_k` | `gateway_server::rag` | `pub` nearest-neighbour count |
| `ThreatCategory::RagPipeline` | `gateway_server::config` | Governance category for RAG requests |
| `AppConfig::rag` | `gateway_server::config` | `pub` field; `RagConfig::default()` when not configured |

---

For implementation details see:

- `gateway-server/src/rag.rs` — `RagConfig` and `RagEngine`
- `gateway-server/src/bin/ingest.rs` — document ingestion binary
- `gateway-server/src/proxy.rs` — handler imports (`RagConfig`, `RagEngine`)
- `gateway-server/src/config.rs` — `AppConfig` with `rag` field and `ThreatCategory::RagPipeline`
- `gateway-server/tests/rag_integration.rs` — integration test suite

---

## Phase 6 – Streaming Response Handling

Phase 6 adds real-time, **sliding-window security scanning** of SSE token streams produced by upstream LLMs. Secrets and injection echoes that emerge across chunk boundaries are caught and killed mid-stream before they reach the client.

### Architecture

```
Client (stream: true)
      │
      ▼
chat_completions_handler
      │
      ▼
[Injection scan] ──block──▶ 403 SecurityBlocked
      │ allow
      ▼
[Upstream LLM SSE stream]
      │
      ▼
create_secure_sse_stream_tracked()   ← SlidingWindowScanner (200-char window)
      │
      ├─ chunk clean  ──▶  forward to client
      └─ violation    ──▶  emit SSE error event, kill stream, log warning
```

### Key types

| Type | Location | Purpose |
|------|----------|---------|
| `SlidingWindowScanner` | `gateway_core::streaming` | Maintains a 200-character overlap buffer; scans each `data:` delta via `InjectionScanner` + `PiiScanner` |
| `StreamDecision` | `gateway_core::streaming` | `Pass` or `Kill { reason, category }` per chunk |
| `create_secure_sse_stream` | `gateway_server::proxy` | Public function; wraps any `Stream<Item=Result<Bytes,E>>` with security scanning |
| `create_secure_sse_stream_tracked` | `gateway_server::proxy` | Private variant; additionally increments `stream_kills_total` metric |

### SSE kill frame format

When a violation is detected the client receives a final SSE frame:

```
event: error
data: {"error":{"message":"Stream blocked by security policy: <reason>","type":"security_violation","code":403}}

```

The stream then closes immediately with no further chunks forwarded.

### Response headers (streaming)

| Header | Value |
|--------|-------|
| `Content-Type` | `text/event-stream` |
| `Cache-Control` | `no-cache` |
| `Connection` | `keep-alive` |
| `X-Request-ID` | Echo of inbound `X-Request-ID` or generated ID |

---

## Phase 7 – Observability, Metrics & Audit Logging

Phase 7 adds **zero-overhead structured telemetry** to the gateway:

- **Prometheus `/metrics` endpoint** — lock-free atomic counters rendered as Prometheus text.
- **Structured JSON audit log** — one JSON line per request emitted via `tracing` at `INFO` level.
- **`X-Request-ID` propagation** — inbound header echoed through to responses; auto-generated if absent.
- **Upstream latency tracking** — per-request round-trip timing recorded and aggregated as a running mean.

---

### `/metrics` endpoint

```
GET /metrics
```

Returns `text/plain; version=0.0.4` in Prometheus exposition format. Compatible with any Prometheus scraper or Grafana agent.

**Example output:**

```
# HELP gateway_requests_total Total inbound requests received.
# TYPE gateway_requests_total counter
gateway_requests_total 1042

# HELP gateway_injection_blocks_total Requests blocked by prompt injection scanner.
# TYPE gateway_injection_blocks_total counter
gateway_injection_blocks_total 7

# HELP gateway_pii_redactions_total PII/secret redactions applied to responses.
# TYPE gateway_pii_redactions_total counter
gateway_pii_redactions_total 3

# HELP gateway_stream_kills_total SSE streams killed mid-flight by security scanner.
# TYPE gateway_stream_kills_total counter
gateway_stream_kills_total 1

# HELP gateway_upstream_latency_mean_us Mean upstream round-trip latency in microseconds.
# TYPE gateway_upstream_latency_mean_us gauge
gateway_upstream_latency_mean_us 84221
```

**Full counter reference:**

| Metric | Type | Description |
|--------|------|-------------|
| `gateway_requests_total` | counter | All inbound requests (all endpoints) |
| `gateway_injection_blocks_total` | counter | Blocked by injection scanner |
| `gateway_policy_blocks_total` | counter | Blocked by auth or governance |
| `gateway_pii_redactions_total` | counter | PII redactions applied to responses |
| `gateway_stream_kills_total` | counter | SSE streams killed mid-flight |
| `gateway_rag_retrievals_total` | counter | RAG context retrievals performed |
| `gateway_upstream_latency_mean_us` | gauge | Mean upstream latency (µs) |
| `gateway_upstream_latency_us_total` | counter | Cumulative upstream latency (µs) |
| `gateway_upstream_latency_samples_total` | counter | Number of latency samples |

---

### Structured audit log

Every request through `/v1/chat/completions` emits a JSON line to the `tracing` subscriber under the target `gateway_audit`. Configure your subscriber to write this target to a file or ship to a log aggregator (e.g. Loki, Datadog).

**Schema:**

```json
{
  "timestamp":               "2026-10-06T00:00:00Z",
  "request_id":              "req-1234567890",
  "endpoint":                "/v1/chat/completions",
  "model":                   "llama3.2:3b",
  "streaming":               false,
  "injection_detected":      false,
  "pii_redacted":            false,
  "pii_findings_count":      0,
  "stream_killed":           false,
  "rag_retrieval_performed": false,
  "upstream_latency_us":     84221,
  "scan_latency_us":         312,
  "outcome":                 "allowed",
  "block_reason":            null
}
```

**`outcome` values:** `allowed` · `blocked_security` · `blocked_policy` · `upstream_error` · `stream_killed`

> **Note** — `block_reason` is omitted from the JSON when `outcome` is `allowed` (uses `#[serde(skip_serializing_if = "Option::is_none")]`).

---

### `X-Request-ID` propagation

If the client sends an `X-Request-ID` header the gateway echoes it back in all responses. If absent, the gateway generates a monotonic ID of the form `req-NNNNNNNNNN`. The same ID appears in both the audit log and all `tracing` log fields for full request tracing.

---

### Implementation details

| File | Role |
|------|------|
| `gateway-core/src/metrics.rs` | `GatewayMetrics` struct (atomic counters + Prometheus renderer) |
| `gateway-server/src/audit.rs` | `AuditRecord` struct, `RequestOutcome` enum, `generate_request_id()` |
| `gateway-server/src/proxy.rs` | `AppState.metrics`, `metrics_handler`, instrumented `chat_completions_handler`, `create_secure_sse_stream_tracked` |
| `gateway-server/tests/metrics_tests.rs` | 14 integration + unit tests |

### Test coverage

| Test group | Count | Coverage |
|------------|-------|---------|
| `GatewayMetrics` unit | 5 | Zero init, increments, latency mean, Prometheus text, thread safety |
| `AuditRecord` unit | 5 | Defaults, JSON serialization, all outcome variants, field omission |
| `/metrics` endpoint | 3 | Status 200, content-type, body metric names present |
| Request pipeline | 1 | Counter observable via shared `Arc`, X-Request-ID on blocked path |

Run Phase 7 tests only:

```bash
cargo test -p gateway-server --test metrics_tests
```

---

## Phase 8 – Performance Testing, Micro-benchmarks & Latency Analysis

Phase 8 provides microsecond-level benchmarking and load testing suites to evaluate the throughput and latency overhead of the gateway.

### Benchmarking Tools

1. **Criterion Micro-benchmarks (`gateway-core/benches/core_benchmarks.rs`)**:
   Measures isolated execution times of `normalize_for_scan`, `InjectionScanner`, `PiiScanner` (including Luhn check), and `SlidingWindowScanner`.

2. **End-to-End Pipeline Concurrency Simulator (`gateway-server/src/bin/benchmark.rs`)**:
   Simulates multi-threaded request streams (1 to 64 workers) measuring $p_{50}$, $p_{90}$, $p_{95}$, and $p_{99}$ latency percentiles and throughput (RPS).

### Performance Summary

| Scenario | Throughput | $p_{50}$ Latency | $p_{99}$ Latency | Sub-ms SLA (<1ms) |
|---|---|---|---|:---:|
| **Single Worker** | 225,198 RPS | 3 µs (0.003 ms) | 9 µs (0.009 ms) | ✅ **PASSED** |
| **64 Concurrent Workers** | **982,817 RPS** | **6 µs (0.006 ms)** | **13 µs (0.013 ms)** | ✅ **PASSED (76x faster than SLA)** |

### Running Benchmarks

```bash
# Run Criterion micro-benchmarks
cargo bench -p gateway-core

# Run High-Concurrency Load Simulation
cargo run --release --bin benchmark
```

See [PHASE_8_BENCHMARKS.md](file:///c:/Users/JERRY/Desktop/RustGuard/docs/PHASE_8_BENCHMARKS.md) for full statistical reports and comparisons against Python-based gateways.

