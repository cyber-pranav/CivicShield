import type { AnalysisMode } from "../types/analysis";

interface Props {
  mode: AnalysisMode;
  onChange: (mode: AnalysisMode) => void;
}

export function AnalysisModeSelector({ mode, onChange }: Props) {
  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        gap: 8,
        padding: "12px 14px",
        background: "var(--bg-card)",
        border: "1px solid var(--border-subtle)",
        borderRadius: 10,
      }}
    >
      <div
        style={{
          fontSize: "0.78rem",
          fontWeight: 600,
          color: "var(--text-secondary)",
          textTransform: "uppercase",
          letterSpacing: "0.05em",
        }}
      >
        Analysis Mode
      </div>

      {/* STATIC option */}
      <label
        style={{
          display: "flex",
          gap: 10,
          alignItems: "flex-start",
          cursor: "pointer",
          padding: "8px 10px",
          borderRadius: 8,
          border: `1px solid ${mode === "STATIC" ? "var(--accent-blue)" : "var(--border-subtle)"}`,
          background: mode === "STATIC" ? "rgba(96,165,250,0.07)" : "transparent",
          transition: "all 0.15s",
        }}
      >
        <input
          type="radio"
          name="analysis_mode"
          value="STATIC"
          checked={mode === "STATIC"}
          onChange={() => onChange("STATIC")}
          style={{ marginTop: 2, accentColor: "var(--accent-blue)" }}
        />
        <div>
          <div style={{ fontWeight: 600, fontSize: "0.82rem", color: "var(--text-primary)" }}>
            🔒 Static Analysis
          </div>
          <div style={{ fontSize: "0.73rem", color: "var(--text-muted)", marginTop: 2 }}>
            Rule-based + ML only. No external network calls.
            URL strings are not shared with third parties.
          </div>
        </div>
      </label>

      {/* ENRICHED option */}
      <label
        style={{
          display: "flex",
          gap: 10,
          alignItems: "flex-start",
          cursor: "pointer",
          padding: "8px 10px",
          borderRadius: 8,
          border: `1px solid ${mode === "ENRICHED" ? "var(--accent-amber, #f59e0b)" : "var(--border-subtle)"}`,
          background: mode === "ENRICHED" ? "rgba(245,158,11,0.07)" : "transparent",
          transition: "all 0.15s",
        }}
      >
        <input
          type="radio"
          name="analysis_mode"
          value="ENRICHED"
          checked={mode === "ENRICHED"}
          onChange={() => onChange("ENRICHED")}
          style={{ marginTop: 2, accentColor: "#f59e0b" }}
        />
        <div>
          <div style={{ fontWeight: 600, fontSize: "0.82rem", color: "var(--text-primary)" }}>
            🌐 Enriched Analysis
          </div>
          <div style={{ fontSize: "0.73rem", color: "var(--text-muted)", marginTop: 2 }}>
            Static + external threat-intelligence databases (URLhaus, Google Safe Browsing).
          </div>
          {mode === "ENRICHED" && (
            <div
              style={{
                marginTop: 6,
                padding: "5px 8px",
                background: "rgba(245,158,11,0.12)",
                borderRadius: 6,
                fontSize: "0.7rem",
                color: "#fbbf24",
                lineHeight: 1.4,
              }}
            >
              ⚠️ <strong>Privacy notice:</strong> URL strings will be submitted to
              URLhaus and (if configured) Google Safe Browsing. No personal data
              is transmitted — only the URL text.
            </div>
          )}
        </div>
      </label>
    </div>
  );
}
