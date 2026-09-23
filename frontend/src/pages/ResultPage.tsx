import { useState } from "react";
import type { AnalysisResult } from "../types/analysis";
import { VerdictBanner } from "../components/VerdictBanner";
import { EvidenceCard } from "../components/EvidenceCard";
import { UrlRiskRow } from "../components/UrlRiskRow";
import { LimitationDisclaimer } from "../components/LimitationDisclaimer";
import { ThreatIntelPanel } from "../components/ThreatIntelPanel";

interface Props {
  result: AnalysisResult;
  onReset: () => void;
}

export function ResultPage({ result, onReset }: Props) {
  const [showExtractedText, setShowExtractedText] = useState(false);

  const suspiciousEvidence = result.evidence.filter(
    (e) =>
      e.evidence_type !== "GENUINE_SIGNAL" &&
      e.evidence_type !== "PROCESSING_NOTE"
  );
  const genuineEvidence = result.evidence.filter(
    (e) => e.evidence_type === "GENUINE_SIGNAL"
  );

  const isEnriched = result.analysis_mode === "ENRICHED";

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      {/* Back button + mode badge */}
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <button className="btn-outline" onClick={onReset} id="back-btn">
          ← New Analysis
        </button>
        <span style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>
          Input type: {result.input_type_processed}
        </span>
        <span
          style={{
            fontSize: "0.7rem",
            padding: "2px 8px",
            borderRadius: 20,
            background: isEnriched
              ? "rgba(245,158,11,0.15)"
              : "rgba(96,165,250,0.12)",
            border: `1px solid ${isEnriched ? "rgba(245,158,11,0.35)" : "rgba(96,165,250,0.25)"}`,
            color: isEnriched ? "#fbbf24" : "var(--accent-blue)",
            fontWeight: 600,
          }}
        >
          {isEnriched ? "🌐 ENRICHED" : "🔒 STATIC"}
        </span>
      </div>

      {/* Verdict banner */}
      <VerdictBanner result={result} />

      {/* Disclaimer */}
      <LimitationDisclaimer />

      {/* Threat intelligence panel (ENRICHED mode only) */}
      {isEnriched && result.intel_results.length > 0 && (
        <div>
          <div className="section-header" style={{ marginBottom: 8 }}>
            <span className="section-title">External Threat Intelligence</span>
            <span className="section-count">{result.intel_results.length}</span>
          </div>
          <ThreatIntelPanel results={result.intel_results} />
        </div>
      )}

      {/* Recommended actions */}
      <div className="card">
        <div className="section-header">
          <span className="section-title">Recommended Actions</span>
        </div>
        <div className="actions-list">
          {result.recommended_actions.map((action, i) => (
            <div className="action-item" key={i}>
              <span className="action-bullet">{i + 1}</span>
              <span>{action}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Evidence */}
      <div className="result-grid">
        {/* Suspicious signals */}
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          <div className="section-header">
            <span className="section-title">Suspicious Signals</span>
            <span className="section-count">{suspiciousEvidence.length}</span>
          </div>
          <div className="evidence-list">
            {suspiciousEvidence.length > 0 ? (
              suspiciousEvidence.map((item, i) => (
                <EvidenceCard key={i} item={item} />
              ))
            ) : (
              <div className="empty-state">
                <div className="empty-icon">✓</div>
                No suspicious signals found in evidence.
              </div>
            )}
          </div>
        </div>

        {/* Genuine signals + URL analysis */}
        <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
          {/* Genuine signals */}
          {genuineEvidence.length > 0 && (
            <div>
              <div className="section-header">
                <span className="section-title">Positive / Genuine Signals</span>
                <span className="section-count">{genuineEvidence.length}</span>
              </div>
              <div className="evidence-list">
                {genuineEvidence.map((item, i) => (
                  <EvidenceCard key={i} item={item} />
                ))}
              </div>
            </div>
          )}

          {/* URL analysis */}
          {result.url_analyses.length > 0 && (
            <div>
              <div className="section-header">
                <span className="section-title">URL Analysis</span>
                <span className="section-count">{result.url_analyses.length}</span>
              </div>
              <div className="url-list">
                {result.url_analyses.map((ua, i) => (
                  <UrlRiskRow key={i} analysis={ua} />
                ))}
              </div>
            </div>
          )}

          {/* Extracted text */}
          {result.extracted_text && (
            <div>
              <div className="section-header">
                <span className="section-title">Extracted Text</span>
                <button
                  className="collapse-toggle"
                  onClick={() => setShowExtractedText((v) => !v)}
                >
                  {showExtractedText ? "▲ Hide" : "▼ Show"}
                </button>
              </div>
              {showExtractedText && (
                <div className="extracted-text">{result.extracted_text}</div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Official verification */}
      <div className="official-link-card">
        <span className="official-link-icon">🏛️</span>
        <div className="official-link-text">
          <strong>Official Verification:</strong> Check any challan number at{" "}
          <a
            href={result.official_verification_url}
            target="_blank"
            rel="noopener noreferrer"
          >
            {result.official_verification_url}
          </a>{" "}
          — you only need the challan number or vehicle registration number.
          <br />
          <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
            CivicShield does not connect to this portal. This link opens in a
            new tab for you to verify directly.
          </span>
        </div>
      </div>

      {/* Processing notes (technical detail) */}
      {result.processing_notes.length > 0 && (
        <details>
          <summary
            style={{
              cursor: "pointer",
              fontSize: "0.78rem",
              color: "var(--text-muted)",
              marginBottom: 8,
            }}
          >
            Processing Notes ({result.processing_notes.length})
          </summary>
          <div className="processing-notes">
            {result.processing_notes.map((note, i) => (
              <div className="processing-note" key={i}>
                {note}
              </div>
            ))}
          </div>
        </details>
      )}
    </div>
  );
}
