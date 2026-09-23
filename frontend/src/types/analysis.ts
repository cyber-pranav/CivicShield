/**
 * CivicShield — TypeScript type definitions
 * Mirror of backend/models/schemas.py Pydantic models.
 * Keep in sync with the backend schema.
 */

export type EvidenceType =
  | "URL_RISK"
  | "DOMAIN_CHECK"
  | "RULE_MATCH"
  | "LANGUAGE_SIGNAL"
  | "GENUINE_SIGNAL"
  | "PROCESSING_NOTE"
  | "THREAT_INTEL";

export type Severity = "HIGH" | "MEDIUM" | "LOW" | "INFO";

export type Verdict = "Likely Genuine" | "Likely Fraudulent" | "Unable to Verify";

export type RiskLevel = "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";

/** Analysis mode — determines whether external threat-intel is queried */
export type AnalysisMode = "STATIC" | "ENRICHED";

export interface EvidenceItem {
  evidence_type: EvidenceType;
  finding: string;
  severity: Severity;
  explanation: string;
  source: string;
  rule_id: string | null;
}

export interface UrlAnalysisResult {
  url: string;
  risk_level: RiskLevel;
  features: Record<string, number | boolean>;
  evidence: EvidenceItem[];
  ml_prediction: string | null;
  ml_available: boolean;
  note: string | null;
}

/** Threat intelligence result from a single provider (ENRICHED mode only) */
export interface ThreatIntelResult {
  provider: string;
  url: string;
  found: boolean;
  threat_type: string | null;
  threat_url: string | null;
  tags: string[];
  date_added: string | null;
  url_status: string;
  error: string | null;
  provider_available: boolean;
}

export interface AnalysisResult {
  verdict: Verdict;
  risk_level: RiskLevel;
  analysis_mode: AnalysisMode;
  evidence: EvidenceItem[];
  extracted_text: string | null;
  extracted_urls: string[];
  url_analyses: UrlAnalysisResult[];
  intel_results: ThreatIntelResult[];
  verdict_reasoning: string;
  recommended_actions: string[];
  official_verification_url: string;
  disclaimer: string;
  processing_notes: string[];
  input_type_processed: string;
  high_severity_count: number;
  medium_severity_count: number;
  low_severity_count: number;
}

// ─────────────────────────────────────────────────────────────────────────────
// Demo case types
// ─────────────────────────────────────────────────────────────────────────────

export type InputType = "url" | "text" | "image" | "pdf";

export interface DemoCase {
  id: string;
  label: string;
  description: string;
  inputType: InputType;
  content: string;
  expectedVerdict: Verdict;
  badge: string; // e.g. "SYNTHETIC TEST CASE"
}
