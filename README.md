# PCRAG — Proof-Carrying Retrieval-Augmented Generation

> Every RAG answer becomes a **verifiable artifact**: claims are decomposed by an LLM, aligned to evidence via **sentence-transformer embeddings**, verified by a **DeBERTa NLI model**, bound via **SHA-256 hash commitments**, **Ed25519 signed**, logged in a **Merkle transparency tree**, and rendered by a **fail-closed** client that refuses to show anything unverifiable.

```
┌─────────┐    ┌──────────────┐    ┌────────────┐    ┌────────────┐    ┌──────────────┐
│  Query  │───▶│   Retrieve   │──▶│  Generate  │──▶│  Decompose │───▶│    Align     │
│         │    │ BM25 + Dense │    │  (LLM)     │    │  (LLM)     │    │ (Embeddings) │
└─────────┘    │  RRF Fusion  │    └────────────┘    └────────────┘    └──────────────┘
               └──────────────┘                                              │
              ┌──────────────────────────────────────────────────────────────┘
              ▼
        ┌──────────┐    ┌─────────────┐    ┌──────────┐    ┌───────────┐    ┌──────────────┐
        │  Verify  │──▶│  Build Cert │───▶│  JCS +   │──▶│  Merkle   │──▶│   Signed     │
        │  (NLI)   │    │  (SHA-256)  │    │  Ed25519 │    │  Log      │    │  Certificate │
        └──────────┘    └─────────────┘    └──────────┘    └───────────┘    └──────────────┘
                                                                                  │
                          ┌───────────────────────────────────────────────────────┘
                          ▼
                    ┌─────────────┐
                    │ Fail-Closed │  Only verified, entailed claims rendered.
                    │  Renderer   │  Everything else blocked with reason code.
                    └─────────────┘
```

## Key Results

| Metric | Demo (5 queries) | NQ (30 queries) |
|--------|----------------:|----------------:|
| **TDR** (Tamper Detection Rate) | 100% | 89%* |
| **FBR** (False Blocking Rate) | 0% | 0% |
| **UAA** (Utility Under Attack) | 0% | 0%* |
| **Crypto Overhead** | < 4 ms | < 4 ms |
| **End-to-end Latency** | 4,324 ms (LLM) / 23 ms (heuristic) | 3,525 ms |

\* Effective TDR is 100% — apparent < 100% only from no-op attacks (e.g., reordering a single-element span list)

## Features

- **Hybrid Retrieval**: BM25 + dense (all-MiniLM-L6-v2, 384-dim) with Reciprocal Rank Fusion
- **LLM Generation**: Groq LLaMA-3.3-70B-Versatile with evidence-grounding constraints
- **Claim Decomposition**: LLM-based atomic factual claim extraction (with regex fallback)
- **Evidence Alignment**: Sentence-transformer cosine similarity (with Jaccard fallback)
- **NLI Verification**: DeBERTa-v3-xsmall (22M params) entailment scoring
- **Cryptographic Binding**: SHA-256 hash commitments for queries, answers, claims, and spans
- **Digital Signatures**: Ed25519 (RFC 8032) over JCS-canonicalized (RFC 8785) certificates
- **Transparency Log**: CT-style Merkle tree (RFC 6962) with SHA-256 inclusion proofs
- **Fail-Closed Rendering**: Client-side verification with explicit block reason codes
- **194 Automated Tests**: Crypto, schema, attacks, API, CLI, golden vectors, eval suite, statistics
- **8-config Ablation Study**: Component contribution analysis with bootstrap CIs
- **12 Attack Variants**: A1–A7 covering post-hoc tampering and provider equivocation
- **Real Dataset Evaluation**: Natural Questions, HotpotQA, TriviaQA support

## Quick Start

### 1. Install

```bash
pip install -r requirements.txt
```

### 2. Run the API Server

```bash
# Without LLM (heuristic mode — no API key needed):
uvicorn server.app:app --reload --host 0.0.0.0 --port 8000

# With LLM (full pipeline):
GROQ_API_KEY=your_key uvicorn server.app:app --reload --host 0.0.0.0 --port 8000
```

The server auto-detects `GROQ_API_KEY` and configures the pipeline accordingly.

### 3. Generate a Certificate

```bash
curl -s -X POST http://localhost:8000/pcrag/answer \
  -H "Content-Type: application/json" \
  -d '{"query": "What is Python?"}' | python -m json.tool
```

### 4. Verify a Certificate (CLI)

```bash
# Save a certificate
curl -s -X POST http://localhost:8000/pcrag/answer \
  -H "Content-Type: application/json" \
  -d '{"query": "What is Ed25519?"}' > cert.json

# Extract public key from response
PK=$(python -c "import json; d=json.load(open('cert.json')); print(d['public_key'])")

# Wrap for CLI format
python -c "
import json
d = json.load(open('cert.json'))
out = {'certificate': d['certificate'], 'signature': d['signature']}
json.dump(out, open('cert_only.json', 'w'), indent=2, default=str)
"

# Verify
python -m verifier_cli.cli verify cert_only.json --public-key "$PK"
```

### 5. Tamper & Detect

```bash
# Tamper the certificate (edit a claim)
python -c "
import json
d = json.load(open('cert_only.json'))
d['certificate']['claims'][0]['claim_text'] = 'TAMPERED!'
json.dump(d, open('tampered.json', 'w'), indent=2, default=str)
"

# Verify tampered cert (should FAIL)
python -m verifier_cli.cli verify tampered.json --public-key "$PK"
# Exit code 1 — FAIL-CLOSED
```

### 6. Run Evaluation

```bash
# Full evaluation (heuristic + LLM + NQ + ablation):
GROQ_API_KEY=your_key python -m eval.generate_report

# Heuristic-only evaluation (no API key needed):
python -m eval.generate_report

# Outputs: PCRAG_Evaluation_Report.md + PCRAG_Evaluation_Results.json
```

### 7. Run Tests

```bash
python -m pytest tests/ -v
# 194 tests covering crypto, schema, attacks, API, CLI, golden vectors,
# claims, spans, retriever, transparency log, metrics, cross-system verification,
# evaluation suite, statistics, and ablation framework
```
# claims, spans, retriever, transparency log, metrics, cross-system verification
```

### 8. React Renderer UI

```bash
cd renderer_web
npm install
npm run dev
# Open http://localhost:5173
# Enter query → certificate is generated, verified client-side, and rendered fail-closed
```

---

## Architecture

```
PCRAG/
├── core/                    # Core library
│   ├── schema.py           # Pydantic v2 certificate models
│   ├── canonicalize.py     # RFC 8785 JCS canonicalization
│   ├── crypto.py           # Ed25519 + SHA-256
│   ├── certificate.py      # Certificate builder
│   ├── claims.py           # Claim extraction (LLM + regex fallback)
│   ├── spans.py            # Evidence span selection (embeddings + Jaccard)
│   ├── verifier_nli.py     # NLI verifier (DeBERTa + heuristic fallback)
│   ├── retriever.py        # Hybrid retriever (BM25 + dense, RRF fusion)
│   ├── embeddings.py       # Sentence-transformer wrapper
│   ├── llm.py              # Groq LLM client (generation + decomposition)
│   ├── transparency.py     # CT-style Merkle transparency log
│   └── pipeline.py         # Configurable end-to-end pipeline
├── server/                  # FastAPI server
│   ├── app.py              # API endpoints (auto-detects LLM availability)
│   └── models.py           # Request/response models
├── verifier_cli/            # Independent CLI verifier
│   └── cli.py
├── renderer_web/            # React fail-closed renderer
│   └── src/
│       ├── CertificateVerifier.ts  # Client-side verification
│       ├── App.tsx
│       └── components/
├── attacks/                 # Tamper attack harness
│   └── tamper.py           # A1-A7 attacks (12 variants)
├── data/                    # Dataset loaders
│   └── loader.py           # NQ, HotpotQA, TriviaQA
├── eval/                    # Evaluation suite
│   ├── metrics.py          # TDR, FBR, UAA, EDR, overhead
│   ├── statistics.py       # Bootstrap CIs, paired significance tests
│   ├── run_eval.py         # Basic report generator
│   ├── full_eval.py        # Full eval with answer quality metrics
│   ├── ablation.py         # 8-config ablation framework
│   └── generate_report.py  # IEEE Access report generator
├── tests/                   # Test suite (194 tests)
│   ├── test_canonicalize.py
│   ├── test_crypto.py
│   ├── test_schema.py
│   ├── test_certificate.py
│   ├── test_pipeline.py
│   ├── test_attacks.py
│   ├── test_golden_vectors.py
│   ├── test_verifier_cli.py
│   ├── test_api.py
│   ├── test_claims.py
│   ├── test_spans.py
│   ├── test_retriever.py
│   ├── test_transparency.py
│   ├── test_metrics.py
│   ├── test_cross_system.py
│   ├── test_eval_suite.py
│   └── test_statistics.py
└── golden/                  # Golden test vectors
    └── golden_certificate.json
```

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/pcrag/answer` | Generate RAG answer + signed certificate |
| POST | `/pcrag/verify` | Verify certificate signature + hash commitments |
| GET | `/pcrag/evidence-bundle/{id}` | Retrieve evidence spans for a certificate |
| GET | `/pcrag/transparency/sth` | Get signed tree head from transparency log |
| GET | `/pcrag/transparency/proof/{leaf_index}` | Get Merkle inclusion proof for a certificate |

---

## Certificate Format

The **AnswerCertificate** (defined in `core/schema.py`) binds:

- **Query commitment** — SHA-256 hash of the query + session nonce
- **Retrieval commitment** — content hashes of all retrieved documents
- **Answer commitment** — SHA-256 hash of the full answer text
- **Claims** — each with:
  - `claim_hash` — SHA-256 of claim text
  - `evidence_spans[]` — each with `span_hash` (SHA-256 of span text)
  - `verification` — NLI label + confidence + verifier identity
  - `render_decision` — `rendered` boolean + reason code

Canonicalized via **RFC 8785 (JCS)**, signed with **Ed25519 (RFC 8032)**.

---

## Threat Model

| Attack | Description | Detection |
|--------|-------------|-----------|
| A1: Citation swap | Swap cited doc_ids | Signature invalidation |
| A2: Span substitution | Edit evidence text | Span hash mismatch + signature |
| A3: Claim edit | Modify claim text | Claim hash mismatch + signature |
| A4: Evidence drop/reorder | Remove or reorder spans | Signature invalidation |
| A5: UI tamper | Fake "verified" labels | Signature invalidation |
| A6: Replay | Reuse old cert for new query | Query hash mismatch (presented vs. committed) |
| A7: Equivocation | Provider issues different certs for same query | Transparency log cross-reference |

**Ablation Study** (5 queries × 12 attack variants × 8 configurations):

| Config | TDR | EDR | Key Missing Detections |
|--------|-----|-----|------------------------|
| **C0 Full** (signing + tlog) | **100%** | **100%** | None |
| **C1** (no signing) | 58.3% | 100% | A1, A4×3, A5 |
| **C2** (no transparency) | 91.7% | 0% | A7 |
| **C7 Minimal** (no crypto) | 50.0% | 0% | A1, A4×3, A5, A7 |

- **Signing adds +41.7 pp TDR** — catches structural attacks undetectable by hashing
- **Transparency adds +8.3 pp TDR and 100% EDR** — sole defense against equivocation
- **FBR: 0%** across all configurations — no false blocking

---

## Fail-Closed Policy

The renderer enforces:

1. **Signature must verify** — Ed25519 over JCS canonical bytes
2. **Hash commitments must match** — answer, claim, and span text hashes
3. **Only `entailed` claims with confidence ≥ threshold render**
4. **Everything else is blocked** with a reason code:
   - `LOW_CONF` — below confidence threshold
   - `NO_SPAN` — no evidence spans found
   - `CONTRADICTED` — evidence contradicts claim
   - `NOT_SUPPORTED` — evidence doesn't support claim
   - `HASH_MISMATCH` — tampering detected
   - `SIGNATURE_INVALID` — certificate signature failed

---

## Pipeline Modes

PCRAG supports a configurable pipeline via `PipelineConfig`:

| Mode | Generation | Claims | Retrieval | Spans | Verifier | Latency |
|------|-----------|--------|-----------|-------|----------|--------:|
| **Full (C0)** | LLM (Groq) | LLM | Hybrid (BM25+Dense) | Embeddings | NLI (DeBERTa) | ~3,578 ms |
| **Minimal (C7)** | Heuristic | Regex | BM25 only | Jaccard | Keyword overlap | ~20 ms |

All modes produce cryptographically signed certificates with identical security
guarantees. The ML components improve answer quality and evidence alignment but
are not required for tamper detection.

```python
from core.pipeline import PCRAGPipeline, PipelineConfig

# Full LLM-enhanced pipeline
config = PipelineConfig(
    use_llm_generation=True,
    use_llm_claims=True,
    use_embedding_spans=True,
    verifier_mode="nli",
    retrieval_mode="hybrid",
)

# Lightweight heuristic pipeline (no API key needed)
config = PipelineConfig(
    use_llm_generation=False,
    use_llm_claims=False,
    use_embedding_spans=False,
    verifier_mode="heuristic",
    retrieval_mode="bm25",
)
```

---

## Transparency Log

Certificates are appended to a **CT-style Merkle transparency log** (`core/transparency.py`):

- **Leaf hashing** — `SHA-256(0x00 || data)` domain separation
- **Internal nodes** — `SHA-256(0x01 || left || right)`
- **Inclusion proofs** — standard Merkle audit path with support for non-power-of-2 trees
- **Signed Tree Head (STH)** — Ed25519-signed `(tree_size, root_hash, timestamp)` tuple

Each certificate embeds a `TransparencyRecord` with its leaf hash, inclusion proof, and STH.

---

## Crypto Details

| Component | Standard | Implementation |
|-----------|----------|----------------|
| Canonicalization | RFC 8785 (JCS) | Custom implementation in `core/canonicalize.py` |
| Signing | RFC 8032 (Ed25519) | `cryptography` library |
| Hashing | SHA-256 | `hashlib` (Python) / `js-sha256` (browser) |
| Key format | Raw 32-byte | Base64-encoded for transport |
| Transparency log | RFC 6962-inspired | Merkle tree in `core/transparency.py` |

---

## License

MIT
