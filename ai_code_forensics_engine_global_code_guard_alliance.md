# AI Code Forensics Engine — Global CodeGuard Alliance

## Purpose
Design a lawful, privacy-respecting AI Forensics Engine that detects unauthorized use of code (GitHub, model weights, repos) and produces reproducible, court-ready evidence packages anchored on the MetaFOX ledger via ClydeOS.

This blueprint is intended for defensive, legal, and compliance uses only — to help creators show provenance and to support legitimate litigation or takedown requests.

---

## 1. High-level Architecture

```
Ingest Layer  ->  Normalization & Hashing  ->  Fingerprint Index  ->  Embedding Store
        \                                               |
         -> Code Similarity Engine (approx search) ------+
         -> Model Exposure Detector                      
                |
        Evidence Builder -> ChainProof Notarizer -> Supabase Case DB -> MetaFOX NFT Anchor
```

### Components
- **Ingest Layer:** Collects public and client-provided repositories (GitHub, Bitbucket, private uploads). Uses authenticated API access and user consent.
- **Normalization & Hashing:** Strips non-functional differences (whitespace, comments, formatting), normalizes identifiers optionally, computes multi-granular hashes (file-level, function-level, token-level) using SHA-3-512 and structural hashing (AST-based).
- **Fingerprint Index:** Compact signatures for quick match filtering (e.g., rolling hash, SimHash, MinHash for n-grams).
- **Embedding Store:** Vector embeddings of code (e.g., codeBERT, StarCoder embeddings) stored in a vector DB (Pinecone, Weaviate, or open-source alternatives). Supports ANN (approx nearest neighbor) search.
- **Similarity Engine:** Two-phase: coarse filter via fingerprint + ANN embeddings, then precise similarity via AST diffing, token sequence alignment (Wagner–Fischer), and semantic comparison using LLMs for paraphrase detection.
- **Model Exposure Detector:** Scans model release notes, training corpora manifests (where available), and model outputs to detect probable ingestion of client code (statistical sampling and watermark detection where applicable).
- **Evidence Builder:** Compiles a human- and machine-readable report: matched snippets, hash proofs, timeline (git commit history), provenance chain, similarity scores, and reproducible query scripts.
- **ChainProof Notarizer:** Hashes the evidence bundle (SHA-3-512), records it to the MetaFOX ledger, and mints an evidence NFT (optional) to anchor provenance.
- **Case DB & Dashboard:** Supabase tables (cases, evidence, audit) and dashboard integration for lawyers and authorized parties.

---

## 2. Data Handling & Privacy (must be enforced)
- **Consent-first ingestion:** Private repos are processed only with explicit owner consent & signed intake forms.
- **Minimization:** Store only required metadata and hashed artifacts where feasible; avoid storing full private code unless necessary and explicitly authorized.
- **Row-level encryption:** Case data encrypted at rest; keys controlled by Alliance (multi-sig key escrow) and accessible only to designated attorneys.
- **Right to be forgotten:** For non-evidentiary datasets, implement deletion workflows aligned with GDPR.
- **Logging & Transparency:** All forensic actions logged and periodically audited; logs hashed and anchored.
- **Audit Trail:** Every evidence package includes automated chain-of-custody metadata: who ran the scan, when, which datasets, and which queries.

---

## 3. Technical Methods & Algorithms

### Normalization
- Remove comments and docstrings (optionally keep if author-specific markers present).
- Normalize whitespace and line endings.
- Optionally rename local identifiers (alpha-renaming) to focus on structure.

### Hashing
- **SHA-3-512** file hash for raw content anchoring.
- **AST-based structural hash**: parse into AST, canonicalize node ordering where possible, and serialize to compute structural hash — robust to formatting changes.
- **Token N-gram rolling hashes** for sliding-window fingerprinting (use Rabin-Karp style rolling hash).

### Fingerprinting & Fast Filter
- **MinHash/LSH** for near-duplicate detection across large corpora.
- **SimHash** for sentence-level similarity.
- Two-tier filtering: (1) fingerprint LSH to find candidate files/functions, (2) ANN search on embeddings.

### Embeddings & Semantic Search
- Use a code-aware embedding model (CodeBERT, StarCoder embeddings) to encode functions and files.
- Store in vector DB with HNSW or IVF indexes for speed and scale.
- Query returns top-K candidates with distances; thresholding + normalized scoring applied.

### Precise Similarity Scoring
- **Token sequence alignment** (edit distance normalized by length) for literal copying detection.
- **AST diff scoring** for structural copying (weights for control flow, API calls, and unique logic constructs).
- **Semantic similarity via LLM**: produce a paraphrase likelihood score (LLM prompted to judge whether two code snippets implement the same unique logic).
- **Composite score:** weighted sum of normalized scores: `S = w1*token_sim + w2*ast_sim + w3*embed_sim + w4*llm_semantic`.

---

## 4. Evidence Package (Court-Ready)
Each evidence bundle must include:
1. **Executive summary:** short description suitable for courts.
2. **Data provenance:** repo URL, commit SHAs, timestamps, author identities (where available), permission receipts.
3. **Matched snippets:** side-by-side comparison with line numbers, normalized forms, and raw originals.
4. **Similarity breakdown:** per-snippet scores and composite score with method descriptions.
5. **Hash proofs:** SHA-3-512 for raw files, AST hashes, and evidence bundle hash.
6. **Chain-of-custody logs:** who executed scans, IP addresses, signed logs.
7. **Automated reproduction script:** a script to re-run the exact query (containerized) to reproduce results.
8. **On-chain anchor:** MetaFOX transaction ID and NFT cert linking to IPFS location of the bundle (or encrypted bundle pointer).

**Format:** PDF + machine-readable JSON manifest + containerized replay script (Dockerfile + exact tool versions).

---

## 5. Legal Admissibility & Best Practices
- **Repeatable Methodology:** All detection steps are deterministic or fully recorded with seeds for randomness; reproducibility is essential.
- **Expert Affidavit:** For court use, pair the evidence package with an expert declaration from the Digital Forensics Lead explaining methods and limitations.
- **Preservation Letter:** Issue legal preservation notices to relevant parties and hosts as early as possible.
- **Data Minimization in Filings:** File only what is necessary in public court records; keep sensitive parts encrypted and available under discovery.
- **Jurisdictional Considerations:** Tailor evidence collection to local rules (e.g., EU data privacy, US ESI rules). Use local counsel from Chamber-approved partners.

---

## 6. Compliance Workflow
1. **Intake & Consent:** Signed digital intake form; record scope and retention.
2. **Pre-scan:** Index only metadata to identify potential hits (low-privacy operation).
3. **Confirm Hit with Owner:** If a hit is found on public or third-party code, notify owner and confirm next steps.
4. **Full Forensic Scan:** If authorized, run full analysis and generate evidence bundle.
5. **Notarize & Anchor:** Hash and record evidence on MetaFOX; mint evidence NFT if desired.
6. **Legal Action/Preservation:** Counsel prepares filings, attaches redacted summary; full bundle available under protective order.

---

## 7. Sample Modules & Code Snippets
### 7.1 Repo Scanner (Python) — high level
```python
# repo_scan.py (simplified)
import os
from git import Repo
import hashlib

def sha3_512(data: bytes) -> str:
    import hashlib
    return hashlib.sha3_512(data).hexdigest()

def clone_repo(url, dest):
    Repo.clone_from(url, dest)

def normalize_code(src: str) -> str:
    # remove comments (language-specific), normalize whitespace
    # placeholder: call tree-sitter or language parser for production
    return ' '.join(src.split())

def file_hash(path):
    with open(path,'rb') as f:
        return sha3_512(f.read())

if __name__ == '__main__':
    clone_repo('https://github.com/example/repo.git','/tmp/repo')
    for root, _, files in os.walk('/tmp/repo'):
        for f in files:
            if f.endswith('.py'):
                p = os.path.join(root,f)
                with open(p,'r',encoding='utf-8',errors='ignore') as fh:
                    norm = normalize_code(fh.read())
                    print(p, sha3_512(norm.encode('utf-8')))
```

### 7.2 Embedding Query (Python pseudo)
```python
from transformers import AutoTokenizer, AutoModel
import numpy as np

# load code embedding model
# encode function-level snippets and query

def embed_text(model, tokenizer, text):
    # tokenization + mean pooling implementation
    return np.random.rand(768)

query_vec = embed_text(model, tokenizer, query_snippet)
# ANN search in vector DB -> return candidates
```

### 7.3 Evidence Bundle Template (JSON)
```json
{
  "case_id": "",
  "bundle_hash": "",
  "matches": [
    {
      "source_repo": "",
      "source_commit": "",
      "target_repo": "",
      "target_commit": "",
      "snippet_source": "",
      "snippet_target": "",
      "scores": { "token_sim": 0.92, "ast_sim": 0.85, "embed_sim": 0.89 }
    }
  ],
  "metafox_tx": "0x...",
  "created_at": "2025-11-04T00:00:00Z"
}
```

---

## 8. Deployment & Scaling
- **Containerization:** Package scanner, embedding, and similarity services as Docker images; orchestrate with Kubernetes.
- **Vector DB:** Use managed or self-hosted ANN (Weaviate, Milvus, Pinecone). Index by function and file.
- **Batching & Throttling:** Respect GitHub rate limits; use caching layers and incremental index updates.
- **Cost Controls:** Hot index for recent clients; cold archive for historical corpora.

---

## 9. Monitoring & QA
- Unit tests for normalization, hashing, and embedding pipelines.
- End-to-end reproducibility tests using seeded runs and stored containers.
- False-positive review pipeline (human-in-the-loop for borderline matches).
- Regular third-party algorithmic audits and red-team tests.

---

## 10. Governance & Ethics Safeguards
- **Use-policy:** Only process data when client-consent or lawful basis exists.
- **Oversight Board Review:** Every automated mass-scan program requires Chamber and Ethics Board approval.
- **Appeal & Correction:** Provide processes for alleged false positives to request re-analysis and removal.
- **Transparency Reports:** Quarterly disclosure about scans performed, cases opened, and outcomes — anonymized.

---

## 11. Next Steps & Deliverables
1. Build prototype: repo scanner + embedding + simple ANN search (2–4 weeks).
2. Add AST-based comparator and evidence bundler (2–3 weeks).
3. Integrate notarization (MetaFOX) and Supabase case flow (1–2 weeks).
4. Pilot with 5 founding members, gather feedback, iterate (4–8 weeks).

---

**Author:** Brandon R. Clyde — Founder & Chief Architect, ClydeOS  ♾️

*Note: This blueprint is for lawful, defensive, and compliance-oriented use. The Alliance will not deploy surveillance or tools to track individuals without proper legal authority and consent.*