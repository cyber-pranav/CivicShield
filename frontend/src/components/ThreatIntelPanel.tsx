import type { ThreatIntelResult } from "../types/analysis";

interface Props {
  results: ThreatIntelResult[];
}

const _statusColor: Record<string, string> = {
  online:  "#f87171",
  offline: "#6ee7b7",
  unknown: "var(--text-muted)",
};

export function ThreatIntelPanel({ results }: Props) {
  if (!results || results.length === 0) return null;

  const hits = results.filter((r) => r.found && !r.error);
  const clean = results.filter((r) => !r.found && !r.error && r.provider_available);
  const errors = results.filter((r) => r.error);

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        gap: 10,
        padding: "12px 14px",
        background:
          hits.length > 0
            ? "rgba(239,68,68,0.06)"
            : "rgba(110,231,183,0.05)",
        border: `1px solid ${hits.length > 0 ? "rgba(239,68,68,0.25)" : "rgba(110,231,183,0.2)"}`,
        borderRadius: 10,
      }}
    >
      <div
        style={{
          fontSize: "0.78rem",
          fontWeight: 700,
          color: hits.length > 0 ? "#f87171" : "#6ee7b7",
          textTransform: "uppercase",
          letterSpacing: "0.05em",
        }}
      >
        {hits.length > 0
          ? `🚨 Threat Intelligence: ${hits.length} Confirmed Hit${hits.length > 1 ? "s" : ""}`
          : "✔ Threat Intelligence: No Matches Found"}
      </div>

      {/* Confirmed hits */}
      {hits.map((r, i) => (
        <div
          key={i}
          style={{
            padding: "8px 10px",
            background: "rgba(239,68,68,0.10)",
            border: "1px solid rgba(239,68,68,0.3)",
            borderRadius: 8,
          }}
        >
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              gap: 8,
            }}
          >
            <span style={{ fontWeight: 600, fontSize: "0.8rem", color: "#fca5a5" }}>
              {r.provider}
            </span>
            <span
              style={{
                fontSize: "0.68rem",
                padding: "1px 6px",
                borderRadius: 4,
                background: "rgba(239,68,68,0.3)",
                color: "#fca5a5",
              }}
            >
              {(r.threat_type || "malicious").toUpperCase()}
            </span>
          </div>
          <div
            style={{
              fontSize: "0.72rem",
              color: "var(--text-muted)",
              marginTop: 4,
              wordBreak: "break-all",
            }}
          >
            {r.url.length > 80 ? r.url.slice(0, 80) + "…" : r.url}
          </div>
          {r.url_status !== "unknown" && (
            <div style={{ fontSize: "0.7rem", marginTop: 3 }}>
              <span style={{ color: "var(--text-muted)" }}>Status: </span>
              <span style={{ color: _statusColor[r.url_status] || "var(--text-muted)" }}>
                {r.url_status}
              </span>
            </div>
          )}
          {r.tags.length > 0 && (
            <div
              style={{
                display: "flex",
                flexWrap: "wrap",
                gap: 4,
                marginTop: 5,
              }}
            >
              {r.tags.map((t, ti) => (
                <span
                  key={ti}
                  style={{
                    fontSize: "0.65rem",
                    padding: "1px 5px",
                    borderRadius: 4,
                    background: "rgba(239,68,68,0.15)",
                    color: "#fca5a5",
                  }}
                >
                  {t}
                </span>
              ))}
            </div>
          )}
          {r.threat_url && (
            <a
              href={r.threat_url}
              target="_blank"
              rel="noopener noreferrer"
              style={{
                display: "block",
                marginTop: 5,
                fontSize: "0.68rem",
                color: "var(--accent-blue)",
              }}
            >
              View threat report ↗
            </a>
          )}
          {r.date_added && (
            <div style={{ fontSize: "0.68rem", color: "var(--text-muted)", marginTop: 2 }}>
              First reported: {r.date_added}
            </div>
          )}
        </div>
      ))}

      {/* Clean results */}
      {clean.length > 0 && (
        <div
          style={{
            display: "flex",
            flexWrap: "wrap",
            gap: 6,
          }}
        >
          {clean.map((r, i) => (
            <span
              key={i}
              style={{
                fontSize: "0.7rem",
                padding: "2px 8px",
                borderRadius: 20,
                background: "rgba(110,231,183,0.1)",
                border: "1px solid rgba(110,231,183,0.2)",
                color: "#6ee7b7",
              }}
            >
              ✓ {r.provider}: Not found
            </span>
          ))}
        </div>
      )}

      {/* Errors / unavailable */}
      {errors.length > 0 && (
        <div style={{ fontSize: "0.68rem", color: "var(--text-muted)" }}>
          {errors.map((r, i) => (
            <div key={i}>
              {r.provider}: {r.provider_available ? `lookup failed — ${r.error}` : "not configured"}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
