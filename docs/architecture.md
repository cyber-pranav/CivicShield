# CivicShield — Architecture Document

## Overview

CivicShield uses a clean client-server architecture with a React frontend and a Python FastAPI backend. All analysis runs server-side. The frontend is a pure presentation layer.

## Data Flow

```
User Input
    │
    ▼
InputPanel (React)
    │  POST /api/analyze (multipart/form-data)
    ▼
analyze.py router (FastAPI)
    │
    ├── input_processor.py
    │       ├── URL: validate + normalise
    │       ├── Text: extract URLs via regex
    │       ├── Image: OCR via pytesseract → text → extract URLs
    │       └── PDF: PyMuPDF → text + annotations → extract URLs
    │
    ├── url_risk_engine.py (per extracted URL)
    │       ├── Parse URL with urlparse + tldextract
    │       ├── Compute 14 structural features (no network fetch)
    │       ├── Apply rule checks (from url_rules.yaml)
    │       ├── Optional: ML model prediction
    │       └── Return UrlAnalysisResult with evidence list
    │
    ├── challan_rule_engine.py (on full extracted text)
    │       ├── Load rules from language_rules.yaml
    │       └── Match patterns → EvidenceItem per rule
    │
    ├── scam_language_engine.py (on full extracted text)
    │       └── Match general scam patterns → EvidenceItem per rule
    │
    ├── evidence_engine.py
    │       └── Merge + deduplicate all evidence lists
    │
    ├── verdict_engine.py
    │       ├── Count severities
    │       ├── Apply configurable thresholds (from language_rules.yaml)
    │       ├── Produce verdict + risk level + reasoning
    │       └── Build recommended actions list
    │
    └── database.py
            └── Log SHA-256(input) + verdict to SQLite
                (no raw content stored)

AnalysisResult JSON
    │
    ▼
ResultPage (React)
    ├── VerdictBanner
    ├── EvidenceCard (×N)
    ├── UrlRiskRow (×M)
    ├── Recommended Actions
    └── LimitationDisclaimer
```

## Engine Design Principles

### URL Risk Engine
- Computes features **from URL string only** — no network access
- 14 features: length, IP host, scheme, shortener, TLD, dots, hyphens, @, double-slash, path depth, brand keyword, official domain, typosquat distance, APK
- ML model supplements but does not replace rule-based signals
- Every computed feature is included in the response for transparency

### Rule Engines
- Rules defined in YAML — updatable without code changes
- One `EvidenceItem` per matched rule (not per match occurrence)
- Each item has: `evidence_type`, `finding`, `severity`, `explanation`, `source`, `rule_id`
- `rule_id` enables full audit trail from verdict back to YAML rule

### Verdict Engine
- Thresholds configurable in `rules/language_rules.yaml`
- Verdict based on **counted evidence items**, never a fabricated probability
- Reasoning expressed in plain English
- Recommended actions are context-specific (differ between Fraudulent/Genuine/Unable)

### Evidence Engine
- Aggregates evidence from all sources
- Deduplicates by `(rule_id, source, finding[:60])`
- Produces severity counts for downstream verdict logic

## Security Architecture

| Concern | Mitigation |
|---------|-----------|
| SSRF | URLs are never fetched — structural analysis only |
| Malicious PDF | PyMuPDF does not execute PDF JavaScript |
| Malicious Image | Processed in-memory via Pillow, never saved to disk |
| APK execution | Never downloaded or executed |
| Data leakage | Only SHA-256 hash of input stored, not raw content |
| External data exfiltration | No external API calls at inference time |
| File size attacks | 5MB limit for images, 10MB for PDFs enforced in processor |

## Database Schema

```sql
CREATE TABLE analysis_sessions (
    id          INTEGER PRIMARY KEY,
    input_hash  TEXT NOT NULL,      -- SHA-256 of input (no raw content)
    input_type  TEXT NOT NULL,
    verdict     TEXT NOT NULL,
    risk_level  TEXT NOT NULL,
    high_count  INTEGER,
    medium_count INTEGER,
    low_count   INTEGER,
    created_at  DATETIME
);
```

## ML Model

- Algorithm: RandomForestClassifier (scikit-learn)
- Features: 12 URL-structural features
- Training data: PhiUSIIL Phishing URL NLP Dataset
- Class weighting: balanced (handles class imbalance)
- Inference: synchronous, < 1ms per URL
- Fallback: if model file missing, rule-only analysis proceeds
