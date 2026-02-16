# PCRAG Paper Figures — Mermaid Diagram Source

---

## Figure 1: System Model

```mermaid
flowchart TB
    subgraph Users["User Layer"]
        U1[User Interface]
        U2[CLI Verifier]
    end
    
    subgraph Server["PCRAG Server"]
        S1[FastAPI]
        S2[Pipeline Orchestrator]
        S3[Certificate Store]
    end
    
    subgraph KB["Knowledge Base"]
        D1[(Documents)]
        D2[(Embeddings Index)]
    end
    
    subgraph TLog["Transparency Infrastructure"]
        T1[Merkle Log]
        T2[STH Service]
    end
    
    U1 -->|Query| S1
    U2 -->|Verify| S1
    S1 --> S2
    S2 -->|Retrieve| D1
    S2 -->|Dense Search| D2
    S2 -->|Store| S3
    S2 -->|Append| T1
    T1 --> T2
    S1 -->|Certificate| U1
    S1 -->|Verify Result| U2
    
    style Users fill:#e1f5fe
    style Server fill:#fff3e0
    style KB fill:#e8f5e9
    style TLog fill:#fce4ec
```

---

## Figure 2: PCRAG 8-Stage Pipeline

```mermaid
flowchart LR
    subgraph Input["Input"]
        Q[Query]
    end
    
    subgraph Stage1["Stage 1"]
        R[Retrieve]
        R1[BM25]
        R2[Dense]
        R3[RRF Fusion]
    end
    
    subgraph Stage2["Stage 2"]
        G[Generate]
        G1[Groq LLM]
    end
    
    subgraph Stage3["Stage 3"]
        C[Claims]
        C1[LLM Decompose]
    end
    
    subgraph Stage4["Stage 4"]
        S[Spans]
        S1[Embedding Similarity]
    end
    
    subgraph Stage5["Stage 5"]
        V[Verify]
        V1[DeBERTa NLI]
    end
    
    subgraph Stage6["Stage 6"]
        B[Build Cert]
        B1[SHA-256 Hashes]
    end
    
    subgraph Stage7["Stage 7"]
        SG[Sign]
        SG1[JCS + Ed25519]
    end
    
    subgraph Stage8["Stage 8"]
        TL[Log]
        TL1[Merkle Append]
    end
    
    subgraph Output["Output"]
        SC[SignedCertificate]
    end
    
    Q --> R
    R --> R1 & R2
    R1 & R2 --> R3
    R3 --> G --> G1
    G1 --> C --> C1
    C1 --> S --> S1
    S1 --> V --> V1
    V1 --> B --> B1
    B1 --> SG --> SG1
    SG1 --> TL --> TL1
    TL1 --> SC
    
    style Input fill:#e3f2fd
    style Output fill:#c8e6c9
```

---

## Figure 3: Pipeline Sequence Diagram

```mermaid
sequenceDiagram
    participant U as User
    participant S as FastAPI Server
    participant R as Retriever
    participant G as Generator
    participant C as Claim Extractor
    participant SP as Span Selector
    participant V as Verifier
    participant B as Cert Builder
    participant K as Crypto
    participant T as Transparency Log

    U->>S: POST /pcrag/answer
    S->>R: retrieve(query, top_k)
    R-->>S: DocumentChunk[]
    S->>G: generate_answer(query, evidence)
    G-->>S: answer_text
    S->>C: extract_claims(answer_text)
    C-->>S: claim_texts[]
    loop For each claim
        S->>SP: select_evidence_spans(claim, chunks)
        SP-->>S: spans[]
        S->>V: verify(claim, evidence_texts)
        V-->>S: Verification(label, confidence)
    end
    S->>B: build_certificate(...)
    B->>K: sha256_hex(texts)
    K-->>B: hash commitments
    B->>K: sign_json(cert, private_key)
    K-->>B: signature_b64
    B-->>S: SignedCertificate
    S->>T: append_certificate(sig, cert_id, issued_at)
    T-->>S: InclusionProof + STH
    S-->>U: AnswerResponse(cert, sig, pk)
```

---

## Figure 4: Certificate Schema Class Diagram

```mermaid
classDiagram
    class SignedCertificate {
        +AnswerCertificate certificate
        +str signature
        +str public_key
    }
    
    class AnswerCertificate {
        +str schema_version
        +str certificate_id
        +str issued_at
        +Issuer issuer
        +QueryCommitment query_commitment
        +RetrievalCommitment retrieval_commitment
        +AnswerCommitment answer_commitment
        +list~ClaimRecord~ claims
        +RenderPolicy policy
        +TransparencyRecord transparency
    }
    
    class ClaimRecord {
        +str claim_id
        +str claim_text
        +str claim_hash
        +list~SpanRecord~ evidence_spans
        +Verification verification
        +RenderDecision render_decision
    }
    
    class SpanRecord {
        +str span_id
        +str doc_id
        +str span_text
        +str span_hash
        +float alignment_score
        +int start_offset
        +int end_offset
    }
    
    class Verification {
        +VerificationLabel label
        +float confidence
        +str verifier_id
        +str verifier_version
        +str verifier_inputs_hash
    }
    
    class RenderDecision {
        +bool rendered
        +BlockReasonCode reason_code
    }
    
    class QueryCommitment {
        +str query_hash
        +str session_nonce
    }
    
    class AnswerCommitment {
        +str answer_text
        +str answer_text_hash
    }
    
    class TransparencyRecord {
        +str log_id
        +str leaf_hash
        +list~str~ inclusion_proof
        +str signed_tree_head
    }

    SignedCertificate *-- AnswerCertificate
    AnswerCertificate *-- ClaimRecord
    AnswerCertificate *-- QueryCommitment
    AnswerCertificate *-- AnswerCommitment
    AnswerCertificate *-- TransparencyRecord
    ClaimRecord *-- SpanRecord
    ClaimRecord *-- Verification
    ClaimRecord *-- RenderDecision
```

---

## Figure 5: Attack Taxonomy

```mermaid
flowchart TB
    subgraph Attacks["Attack Taxonomy — 12 Variants"]
        direction TB
        subgraph PostHoc["Post-Hoc Tampering (A1-A6)"]
            A1[A1: Citation Swap<br/>Swap doc_ids]
            A2[A2: Span Substitution<br/>3 variants]
            A3[A3: Claim Edit<br/>2 variants]
            A4[A4: Structural<br/>3 variants]
            A5[A5: UI Tamper<br/>Fake labels]
            A6[A6: Replay<br/>Reuse cert]
        end
        subgraph Provider["Provider Misbehavior (A7)"]
            A7[A7: Equivocation<br/>Different certs]
        end
    end

    subgraph A2Variants["A2 Variants"]
        A2a[A2a: Insert]
        A2b[A2b: Paraphrase]
        A2c[A2c: Numbers]
    end
    
    subgraph A3Variants["A3 Variants"]
        A3a[A3a: Negate]
        A3b[A3b: Quantifier]
    end
    
    subgraph A4Variants["A4 Variants"]
        A4a[A4a: Drop span]
        A4b[A4b: Drop all]
        A4c[A4c: Reorder]
    end

    A2 --> A2Variants
    A3 --> A3Variants
    A4 --> A4Variants

    subgraph Detection["Detection Mechanisms"]
        SIG[Ed25519 Signature]
        HASH[SHA-256 Hashes]
        QHASH[Query Hash]
        TLOG[Transparency Log]
    end

    A1 --> SIG
    A2 --> HASH
    A3 --> HASH
    A4 --> SIG
    A5 --> SIG
    A6 --> QHASH
    A7 --> TLOG
    
    style PostHoc fill:#ffcdd2
    style Provider fill:#fff9c4
    style Detection fill:#c8e6c9
```

---

## Figure 6: Merkle Tree Structure

```mermaid
flowchart TB
    subgraph Tree["Merkle Tree"]
        ROOT[Root Hash<br/>H₀₋₃]
        N01[H₀₋₁]
        N23[H₂₋₃]
        L0[Leaf 0<br/>H₀]
        L1[Leaf 1<br/>H₁]
        L2[Leaf 2<br/>H₂]
        L3[Leaf 3<br/>H₃]
        
        ROOT --> N01
        ROOT --> N23
        N01 --> L0
        N01 --> L1
        N23 --> L2
        N23 --> L3
    end
    
    subgraph Formulas["Hash Formulas"]
        F1["Leaf: H(0x00 || data)"]
        F2["Node: H(0x01 || left || right)"]
        F3["STH: Sign(size || root || time)"]
    end
    
    subgraph Proof["Inclusion Proof for L₁"]
        P1["Path: H₀ → H₂₋₃ → verify root"]
        P2["Cost: O(log n) hashes"]
    end
    
    style Tree fill:#e3f2fd
    style Formulas fill:#fff3e0
    style Proof fill:#e8f5e9
```

---

## Figure 7: Verification Flow

```mermaid
sequenceDiagram
    participant U as User/Auditor
    participant V as Verifier
    participant K as Crypto
    participant R as Renderer

    U->>V: certificate + signature + public_key
    V->>K: JCS canonicalize(cert)
    K-->>V: canonical_bytes
    V->>K: Ed25519 verify(canonical_bytes, sig, pk)
    K-->>V: signature_valid
    V->>V: Check answer_text_hash
    V->>V: Check claim_hash (each claim)
    V->>V: Check span_hash (each span)
    V->>V: Check query_hash (replay detection)
    V-->>R: VerificationResult
    alt All checks pass
        R->>R: Render entailed + high-conf claims
    else Any check fails
        R->>R: BLOCK all claims (fail-closed)
    end
```

---

## Figure 8: Component Dependency Graph

```mermaid
flowchart LR
    subgraph Leaf["Leaf Modules"]
        schema[schema.py]
        canon[canonicalize.py]
        emb[embeddings.py]
        llm[llm.py]
        stats[statistics.py]
        loader[loader.py]
    end

    subgraph Mid["Mid-Level"]
        crypto[crypto.py]
        claims[claims.py]
        spans[spans.py]
        retriever[retriever.py]
        verifier[verifier_nli.py]
        tlog[transparency.py]
        cert[certificate.py]
        metrics[metrics.py]
        tamper[tamper.py]
    end

    subgraph Top["Top-Level"]
        pipeline[pipeline.py]
        server[app.py]
        cli[cli.py]
        ablation[ablation.py]
        fulleval[full_eval.py]
        report[generate_report.py]
    end

    crypto --> canon
    claims -.-> llm
    spans -.-> emb
    retriever --> spans
    retriever -.-> emb
    verifier --> schema
    tlog --> crypto
    cert --> canon
    cert --> crypto
    cert --> schema
    metrics --> canon
    metrics --> crypto

    pipeline --> cert
    pipeline --> claims
    pipeline --> crypto
    pipeline --> retriever
    pipeline --> schema
    pipeline --> spans
    pipeline --> tlog
    pipeline --> verifier
    pipeline -.-> llm
    pipeline -.-> emb

    server --> pipeline
    server --> crypto
    cli --> canon
    cli --> crypto
    ablation --> pipeline
    ablation --> tamper
    ablation --> metrics
    ablation --> stats
    fulleval --> pipeline
    fulleval --> tamper
    fulleval --> metrics
    report --> fulleval
    report --> ablation
    
    style Leaf fill:#e8f5e9
    style Mid fill:#fff3e0
    style Top fill:#e3f2fd
```

---

## Figure 9: React Renderer Component Tree

```mermaid
flowchart TB
    subgraph React["React Renderer"]
        INDEX[index.tsx<br/>React 18 Entry]
        APP[App.tsx<br/>Query + Verify Tabs]
        CV[CertificateVerifier.ts<br/>Client-Side Verification]
        VIEW[CertificateView.tsx<br/>Result Display]
        CARD[ClaimCard.tsx<br/>Per-Claim Card]
    end

    subgraph Verify["Client-Side Verification"]
        JCS2[JCS Canonicalize<br/>TypeScript]
        ED2[Ed25519 Verify<br/>tweetnacl]
        SHA2[SHA-256 Check<br/>js-sha256]
        POLICY[Fail-Closed Policy<br/>Render Logic]
    end

    INDEX --> APP
    APP -->|Query Tab| CV
    APP -->|Verify Tab| CV
    CV --> JCS2
    JCS2 --> ED2
    CV --> SHA2
    ED2 --> POLICY
    SHA2 --> POLICY
    POLICY --> VIEW
    VIEW --> CARD
    
    style React fill:#e3f2fd
    style Verify fill:#fce4ec
```

---

## Figure 10: Evaluation Pipeline

```mermaid
flowchart TB
    subgraph Queries["Evaluation Queries"]
        Q1[Demo<br/>5 queries]
        Q2[NQ<br/>30 queries]
    end

    subgraph Eval["Evaluation Framework"]
        FE[Full Eval<br/>Answer Quality]
        AB[Ablation<br/>8 Configs]
        AT[Attack Harness<br/>12 Variants]
    end

    subgraph Metrics["Metrics Computation"]
        M1[TDR]
        M2[FBR]
        M3[UAA]
        M4[EDR]
        M5[EM/F1/ROUGE]
        M6[Latency/Size]
    end

    subgraph Stats["Statistics"]
        S1[Bootstrap CIs]
        S2[Paired Tests]
    end

    subgraph Output["Output"]
        R1[Report.md]
        R2[Results.json]
    end

    Q1 & Q2 --> FE & AB & AT
    FE --> M5
    AB --> M1 & M2 & M6
    AT --> M1 & M2 & M3 & M4
    M1 & M2 & M3 & M4 & M5 & M6 --> S1 & S2
    S1 & S2 --> R1 & R2
    
    style Queries fill:#e8f5e9
    style Eval fill:#fff3e0
    style Metrics fill:#e3f2fd
    style Stats fill:#fce4ec
    style Output fill:#c8e6c9
```

---

## Figure 11: Cryptographic Signing Flow

```mermaid
flowchart TB
    subgraph Input["Certificate Object"]
        CERT[AnswerCertificate<br/>JSON Structure]
    end
    
    subgraph JCS["JCS Canonicalization"]
        J1[Sort keys<br/>lexicographically]
        J2[Normalize numbers<br/>ES2015 rules]
        J3[Escape strings<br/>JSON spec]
        J4[Remove whitespace]
        J5[canonical_bytes]
    end
    
    subgraph Sign["Ed25519 Signing"]
        S1[Private Key<br/>32 bytes]
        S2[Sign operation<br/>RFC 8032]
        S3[signature<br/>64 bytes]
        S4[base64 encode]
        S5[signature_b64<br/>88 chars]
    end
    
    subgraph Output["SignedCertificate"]
        OUT[certificate + signature]
    end
    
    CERT --> J1 --> J2 --> J3 --> J4 --> J5
    J5 --> S2
    S1 --> S2
    S2 --> S3 --> S4 --> S5
    CERT --> OUT
    S5 --> OUT
    
    style Input fill:#e3f2fd
    style JCS fill:#fff3e0
    style Sign fill:#fce4ec
    style Output fill:#c8e6c9
```

---

## Figure 12: Fail-Closed Render Decision Tree

```mermaid
flowchart TB
    START[Claim to Render?]
    
    SIG{Signature<br/>Valid?}
    HASH{All Hashes<br/>Match?}
    SPAN{Evidence<br/>Spans > 0?}
    LABEL{NLI Label =<br/>entailed?}
    CONF{Confidence ≥<br/>Threshold?}
    
    RENDER[✓ RENDER<br/>Show Claim]
    
    BLOCK1[✗ BLOCK<br/>SIGNATURE_INVALID]
    BLOCK2[✗ BLOCK<br/>HASH_MISMATCH]
    BLOCK3[✗ BLOCK<br/>NO_SPAN]
    BLOCK4[✗ BLOCK<br/>NOT_SUPPORTED]
    BLOCK5[✗ BLOCK<br/>LOW_CONF]
    
    START --> SIG
    SIG -->|No| BLOCK1
    SIG -->|Yes| HASH
    HASH -->|No| BLOCK2
    HASH -->|Yes| SPAN
    SPAN -->|No| BLOCK3
    SPAN -->|Yes| LABEL
    LABEL -->|No| BLOCK4
    LABEL -->|Yes| CONF
    CONF -->|No| BLOCK5
    CONF -->|Yes| RENDER
    
    style START fill:#e3f2fd
    style RENDER fill:#c8e6c9
    style BLOCK1 fill:#ffcdd2
    style BLOCK2 fill:#ffcdd2
    style BLOCK3 fill:#ffcdd2
    style BLOCK4 fill:#ffcdd2
    style BLOCK5 fill:#ffcdd2
```

---

## Figure 13: Ablation Component Contribution

```mermaid
flowchart LR
    subgraph Full["C0: Full Pipeline"]
        F1[LLM Gen]
        F2[LLM Claims]
        F3[Hybrid Ret]
        F4[Emb Spans]
        F5[NLI Ver]
        F6[Ed25519 Sign]
        F7[Merkle Log]
    end
    
    subgraph Ablations["Ablation Configs"]
        C1[C1: No Sign<br/>-41.7% TDR]
        C2[C2: No TLog<br/>-8.3% TDR]
        C3[C3: Regex Claims<br/>No TDR change]
        C4[C4: Heur Ver<br/>No TDR change]
        C5[C5: Jaccard<br/>No TDR change]
        C6[C6: BM25 Only<br/>No TDR change]
        C7[C7: Minimal<br/>-50% TDR]
    end
    
    F6 -.-> C1
    F7 -.-> C2
    F2 -.-> C3
    F5 -.-> C4
    F4 -.-> C5
    F3 -.-> C6
    F1 & F2 & F3 & F4 & F5 & F6 & F7 -.-> C7
    
    style Full fill:#c8e6c9
    style Ablations fill:#ffcdd2
```

---

## Figure 14: API Endpoint Architecture

```mermaid
flowchart TB
    subgraph API["FastAPI Server"]
        E1["POST /pcrag/answer<br/>Generate + Certify"]
        E2["POST /pcrag/verify<br/>Verify Certificate"]
        E3["GET /pcrag/evidence-bundle/{id}<br/>Retrieve Evidence"]
        E4["GET /pcrag/transparency/sth<br/>Get Tree Head"]
        E5["GET /pcrag/transparency/proof/{idx}<br/>Get Inclusion Proof"]
    end
    
    subgraph Internal["Internal Components"]
        P[PCRAGPipeline]
        CS[Certificate Store]
        TL[Transparency Log]
    end
    
    E1 --> P
    P --> CS
    P --> TL
    E2 --> P
    E3 --> CS
    E4 --> TL
    E5 --> TL
    
    style API fill:#e3f2fd
    style Internal fill:#fff3e0
```

