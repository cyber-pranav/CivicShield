import { useState } from "react";
import type { UrlAnalysisResult } from "../types/analysis";
import { EvidenceCard } from "./EvidenceCard";

interface Props {
  analysis: UrlAnalysisResult;
}

// Features to display in the chip grid (and whether flagged=true is bad)
const FEATURE_DISPLAY: Record<string, { label: string; badWhenTrue: boolean }> = {
  has_ip_host:              { label: "IP host",          badWhenTrue: true },
  scheme_is_http:           { label: "HTTP (not HTTPS)", badWhenTrue: true },
  is_url_shortener:         { label: "URL shortener",    badWhenTrue: true },
  suspicious_tld:           { label: "Suspicious TLD",   badWhenTrue: true },
  has_at_symbol:            { label: "@ in URL",         badWhenTrue: true },
  has_double_slash_path:    { label: "// in path",       badWhenTrue: true },
  brand_keyword_in_domain:  { label: "Brand impersonation", badWhenTrue: true },
  apk_in_url:               { label: "APK in URL",       badWhenTrue: true },
  is_official_domain:       { label: "Official domain",  badWhenTrue: false },
};

export function UrlRiskRow({ analysis }: Props) {
  const [expanded, setExpanded] = useState(false);

  const truncatedUrl =
    analysis.url.length > 70 ? analysis.url.slice(0, 70) + "…" : analysis.url;

  return (
    <div className="url-row">
      <div className="url-row-header">
        <span className="url-text" title={analysis.url}>
          {truncatedUrl}
        </span>
        <span className={`risk-badge ${analysis.risk_level}`}>
          {analysis.risk_level}
        </span>
        {analysis.ml_available && analysis.ml_prediction && (
          <span
            className={`risk-badge ${analysis.ml_prediction === "phishing" ? "HIGH" : "LOW"}`}
            title="ML model prediction (supplementary)"
          >
            ML: {analysis.ml_prediction}
          </span>
        )}
        <button
          className="btn-outline"
          onClick={() => setExpanded((e) => !e)}
        >
          {expanded ? "▲ Collapse" : "▼ Details"}
        </button>
      </div>

      {/* Feature chips — always visible */}
      <div className="url-feature-grid">
        {Object.entries(FEATURE_DISPLAY).map(([key, meta]) => {
          const value = analysis.features[key];
          const isFlagged = meta.badWhenTrue
            ? Boolean(value)
            : !Boolean(value);
          // Only show "good" features if they're actually true
          if (!meta.badWhenTrue && !Boolean(value)) return null;
          return (
            <span
              key={key}
              className={`feature-chip ${isFlagged ? "flagged" : ""}`}
              title={key}
            >
              {isFlagged && meta.badWhenTrue ? "⚠ " : ""}
              {meta.label}
              {!meta.badWhenTrue && Boolean(value) ? " ✓" : ""}
            </span>
          );
        })}
        <span className="feature-chip" title="url_length">
          len={analysis.features.url_length as number}
        </span>
      </div>

      {/* Expanded evidence */}
      {expanded && analysis.evidence.length > 0 && (
        <div style={{ marginTop: 12 }}>
          <div className="card-title" style={{ marginBottom: 8 }}>
            URL Evidence
          </div>
          <div className="evidence-list">
            {analysis.evidence.map((e, i) => (
              <EvidenceCard key={i} item={e} />
            ))}
          </div>
        </div>
      )}

      {expanded && analysis.evidence.length === 0 && (
        <div
          style={{
            marginTop: 10,
            fontSize: "0.8rem",
            color: "var(--text-muted)",
          }}
        >
          No specific risk signals found for this URL.
        </div>
      )}
    </div>
  );
}
